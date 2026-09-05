package integration_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type apiResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type integrationSuite struct {
	repoRoot string
	baseURL  string
	wsURL    string
	fmRoot   string
	client   *http.Client
	process  *exec.Cmd
	logs     bytes.Buffer

	adminUser string
	adminPass string
}

var suite integrationSuite

func TestMain(m *testing.M) {
	code := 1
	if err := suite.start(); err != nil {
		fmt.Fprintln(os.Stderr, "integration server startup failed:", err)
		if suite.logs.Len() > 0 {
			fmt.Fprintln(os.Stderr, suite.logs.String())
		}
		os.Exit(code)
	}
	code = m.Run()
	suite.stop()
	os.Exit(code)
}

func (s *integrationSuite) start() error {
	root, err := filepath.Abs("..")
	if err != nil {
		return err
	}
	s.repoRoot = root
	tempDir, err := os.MkdirTemp("", "prtstrike-integration-")
	if err != nil {
		return err
	}
	s.fmRoot = filepath.Join(tempDir, "files")
	if err := os.MkdirAll(s.fmRoot, 0755); err != nil {
		return err
	}

	s.adminUser = "integration-admin"
	s.adminPass = "integration-password-2026"

	executable := filepath.Join(tempDir, "prtstrike-test.exe")
	build := exec.Command("go", "build", "-o", executable, ".")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build failed: %w\n%s", err, output)
	}

	port, err := freePort()
	if err != nil {
		return err
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	s.baseURL = "http://" + address
	s.wsURL = "ws://" + address
	s.process = exec.Command(executable)
	s.process.Dir = root
	s.process.Env = append(os.Environ(),
		"PRTS_ADDR="+address,
		"PRTS_DB_PATH="+filepath.Join(tempDir, "test.db"),
		"PRTS_FM_ROOT="+s.fmRoot,
		"PRTS_SECRET=integration-test-secret-with-sufficient-length",
		"PRTS_ADMIN_USER="+s.adminUser,
		"PRTS_ADMIN_PASS="+s.adminPass,
	)
	s.process.Stdout = &s.logs
	s.process.Stderr = &s.logs
	if err := s.process.Start(); err != nil {
		return err
	}

	jar, _ := cookiejar.New(nil)
	s.client = &http.Client{Jar: jar, Timeout: 15 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := s.client.Get(s.baseURL + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s.login(s.client, s.adminUser, s.adminPass)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("server did not become ready")
}

func (s *integrationSuite) stop() {
	if s.process != nil && s.process.Process != nil {
		_ = s.process.Process.Kill()
		_, _ = s.process.Process.Wait()
	}
	if s.fmRoot != "" {
		_ = os.RemoveAll(filepath.Dir(s.fmRoot))
	}
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (s *integrationSuite) login(client *http.Client, username, password string) error {
	return loginTo(client, s.baseURL, username, password)
}

func loginTo(client *http.Client, baseURL, username, password string) error {
	resp, err := client.PostForm(baseURL+"/api/login", url.Values{
		"username": {username},
		"password": {password},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func requestJSON(client *http.Client, method, target string, body any) (int, apiResponse, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, apiResponse{}, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		return 0, apiResponse{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// The API rejects state-changing requests without the CSRF header.
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := client.Do(req)
	if err != nil {
		return 0, apiResponse{}, err
	}
	defer resp.Body.Close()
	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil && resp.ContentLength != 0 {
		return resp.StatusCode, result, err
	}
	return resp.StatusCode, result, nil
}

// ── Beacon HMAC helpers ──────────────────────────────────

func beaconSignature(key string, body []byte) (ts, nonce, sig string) {
	ts = strconv.FormatInt(time.Now().Unix(), 10)
	// Unique nonce per request: identical poll bodies must not collide in
	// the server's replay cache.
	nonce = strconv.FormatInt(time.Now().UnixNano(), 36)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts + "." + nonce + "."))
	mac.Write(body)
	return ts, nonce, hex.EncodeToString(mac.Sum(nil))
}

// signedBeaconRequest POSTs an HMAC-signed beacon request.
func signedBeaconRequest(t *testing.T, target, key, beaconID string, body []byte) (*http.Response, error) {
	t.Helper()
	ts, nonce, sig := beaconSignature(key, body)
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Beacon-ID", beaconID)
	req.Header.Set("X-Beacon-Timestamp", ts)
	req.Header.Set("X-Beacon-Nonce", nonce)
	req.Header.Set("X-Beacon-Sign", sig)
	return http.DefaultClient.Do(req)
}

// createPayload generates a powershell payload (fast template, no compile) and
// returns its per-payload HMAC key.
func createPayload(t *testing.T, name string) (payloadID, key string) {
	t.Helper()
	listenerID, _ := createListener(t)
	status, response, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/payloads", map[string]any{
		"name": name, "type": "powershell", "listener_id": listenerID,
		"callback_host": "127.0.0.1", "os": "windows",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create payload: status=%d err=%v response=%+v", status, err, response)
	}
	var payload struct {
		ID        string `json:"id"`
		BeaconKey string `json:"beacon_key"`
	}
	if err := json.Unmarshal(response.Data, &payload); err != nil || payload.ID == "" || payload.BeaconKey == "" {
		t.Fatalf("invalid payload response: %s", response.Data)
	}
	return payload.ID, payload.BeaconKey
}

func createListener(t *testing.T) (string, string) {
	return createListenerType(t, "reverse_http")
}

func createListenerType(t *testing.T, listenerType string) (string, string) {
	t.Helper()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	status, response, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/listeners", map[string]any{
		"name": "integration", "type": listenerType, "bind_ip": "127.0.0.1", "port": port,
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create listener: status=%d err=%v response=%+v", status, err, response)
	}
	var listener struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Data, &listener); err != nil || listener.ID == "" {
		t.Fatalf("invalid listener response: %s", response.Data)
	}
	t.Cleanup(func() {
		_, _, _ = requestJSON(suite.client, http.MethodDelete, suite.baseURL+"/api/listeners/"+listener.ID, nil)
	})
	if listenerType == "reverse_tcp" {
		return listener.ID, fmt.Sprintf("127.0.0.1:%d", port)
	}
	return listener.ID, fmt.Sprintf("http://127.0.0.1:%d/checkin", port)
}

func registerBeacon(t *testing.T, callbackURL, key, id string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"beacon_id": id, "hostname": "host-" + id, "username": "tester", "os": "linux", "sleep": 1, "jitter": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := signedBeaconRequest(t, callbackURL, key, id, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register beacon %q: status=%d body=%s", id, resp.StatusCode, data)
	}
}

// pollBeaconTasks performs a signed poll and returns claimed tasks.
func pollBeaconTasks(t *testing.T, callbackURL, key, beaconID string) []struct {
	ID      string `json:"id"`
	Command string `json:"command"`
} {
	t.Helper()
	body := []byte(`{"type":"poll"}`)
	resp, err := signedBeaconRequest(t, callbackURL, key, beaconID, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll beacon: status=%d body=%s", resp.StatusCode, data)
	}
	var tasks []struct {
		ID      string `json:"id"`
		Command string `json:"command"`
	}
	_ = json.Unmarshal(data, &tasks)
	return tasks
}

func submitBeaconResult(t *testing.T, callbackURL, key, beaconID, taskID, output string) (*http.Response, error) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"task_id": taskID, "output": output, "beacon_id": beaconID})
	if err != nil {
		t.Fatal(err)
	}
	return signedBeaconRequest(t, callbackURL, key, beaconID, body)
}

func TestAuthenticationAndPasswordChange(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if err := suite.login(client, suite.adminUser, "wrong-password"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	if err := suite.login(client, suite.adminUser, suite.adminPass); err != nil {
		t.Fatal(err)
	}
	newPassword := "integration-password-2026-b"
	status, _, err := requestJSON(client, http.MethodPost, suite.baseURL+"/api/change-password", map[string]string{
		"old_password": suite.adminPass, "new_password": newPassword,
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("change password: status=%d err=%v", status, err)
	}
	newJar, _ := cookiejar.New(nil)
	newClient := &http.Client{Jar: newJar, Timeout: 10 * time.Second}
	if err := suite.login(newClient, suite.adminUser, suite.adminPass); err == nil {
		t.Fatal("old password remained valid")
	}
	if err := suite.login(newClient, suite.adminUser, newPassword); err != nil {
		t.Fatal(err)
	}
	status, _, err = requestJSON(newClient, http.MethodPost, suite.baseURL+"/api/change-password", map[string]string{
		"old_password": newPassword, "new_password": suite.adminPass,
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("restore password: status=%d err=%v", status, err)
	}
}

// setLegacyBeaconAuth toggles the legacy-compat setting and restores the
// previous value when the test finishes.
func setLegacyBeaconAuth(t *testing.T, enabled bool) {
	t.Helper()
	status, resp, err := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/settings", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("get settings: status=%d err=%v", status, err)
	}
	var settings struct {
		ServerName       string `json:"server_name"`
		SessionTimeout   int    `json:"session_timeout"`
		Theme            string `json:"theme"`
		Debug            bool   `json:"debug"`
		GeoIPLookup      bool   `json:"geoip_lookup"`
		LegacyBeaconAuth bool   `json:"legacy_beacon_auth"`
	}
	if err := json.Unmarshal(resp.Data, &settings); err != nil {
		t.Fatalf("parse settings: %v (data=%s)", err, resp.Data)
	}
	previous := settings.LegacyBeaconAuth
	settings.LegacyBeaconAuth = enabled
	status, _, err = requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/settings", settings)
	if err != nil || status != http.StatusOK {
		t.Fatalf("save settings: status=%d err=%v", status, err)
	}
	t.Cleanup(func() {
		settings.LegacyBeaconAuth = previous
		_, _, _ = requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/settings", settings)
	})
}

// TestLegacyBeaconCompat verifies that payloads built before the HMAC
// upgrade (unsigned HTTP and TCP protocol) keep working while
// Settings.LegacyBeaconAuth is enabled (the default).
func TestLegacyBeaconCompat(t *testing.T) {
	setLegacyBeaconAuth(t, true)

	// ── HTTP legacy protocol ─────────────────────────────
	_, callbackURL := createListener(t)

	// Registration: unsigned POST with CheckInData body (exact old format)
	regBody, _ := json.Marshal(map[string]any{
		"beacon_id": "legacy-http-id", "hostname": "legacy-host", "username": "legacy-user",
		"os": "linux amd64", "sleep": 1, "jitter": 0,
	})
	resp, err := http.Post(callbackURL, "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	regData, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(regData), "REGISTERED") {
		t.Fatalf("legacy register failed: status=%d body=%s", resp.StatusCode, regData)
	}

	// Poll: unsigned GET (the exact old task-stealing-shaped request)
	getTask := func() []struct {
		ID      string `json:"id"`
		Command string `json:"command"`
	} {
		req, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
		req.Header.Set("X-Beacon-ID", "legacy-http-id")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("legacy poll: status=%d body=%s", r.StatusCode, body)
		}
		var tasks []struct {
			ID      string `json:"id"`
			Command string `json:"command"`
		}
		_ = json.Unmarshal(body, &tasks)
		return tasks
	}

	// Idle poll answers the SLEEP directive
	req, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
	req.Header.Set("X-Beacon-ID", "legacy-http-id")
	idleResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	idleBody, _ := io.ReadAll(idleResp.Body)
	idleResp.Body.Close()
	if idleResp.StatusCode != http.StatusOK || !strings.HasPrefix(string(idleBody), "SLEEP ") {
		t.Fatalf("legacy idle poll: status=%d body=%s", idleResp.StatusCode, idleBody)
	}

	// Task delivery + result over the unsigned protocol
	status, taskResp, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/tasks", map[string]string{
		"client_id": "legacy-http-id", "command": "echo legacy",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create task: status=%d err=%v", status, err)
	}
	var task struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(taskResp.Data, &task); err != nil || task.ID == "" {
		t.Fatalf("invalid task response: %s", taskResp.Data)
	}

	tasks := getTask()
	if len(tasks) != 1 || tasks[0].ID != task.ID {
		t.Fatalf("legacy poll did not return the task: %+v", tasks)
	}

	resultBody, _ := json.Marshal(map[string]string{"task_id": task.ID, "output": "legacy-result", "beacon_id": "legacy-http-id"})
	resp, err = http.Post(callbackURL, "application/json", bytes.NewReader(resultBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy result: status=%d", resp.StatusCode)
	}

	_, detail, _ := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+task.ID, nil)
	var current struct{ Status, Result string }
	_ = json.Unmarshal(detail.Data, &current)
	if current.Status != "completed" || current.Result != "legacy-result" {
		t.Fatalf("legacy result not stored: %+v", current)
	}

	// ── TCP legacy protocol ──────────────────────────────
	tcpAddr := createLegacyTCPBeacon(t, "legacy-tcp-id")

	status, taskResp, err = requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/tasks", map[string]string{
		"client_id": "legacy-tcp-id", "command": "echo legacy-tcp",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create tcp task: status=%d err=%v", status, err)
	}
	if err := json.Unmarshal(taskResp.Data, &task); err != nil || task.ID == "" {
		t.Fatalf("invalid task response: %s", taskResp.Data)
	}

	conn, err := net.DialTimeout("tcp", tcpAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Register (unsigned)
	tcpWriteFrame(t, conn, map[string]any{"type": "register", "data": map[string]any{
		"beacon_id": "legacy-tcp-id", "hostname": "legacy-tcp-host", "username": "u", "sleep": 1, "jitter": 0,
	}})
	ack := tcpReadFrame(t, conn)
	if ack["type"] != "ack" {
		t.Fatalf("tcp register ack: %+v", ack)
	}

	// Checkin -> tasks
	tcpWriteFrame(t, conn, map[string]any{"type": "checkin"})
	msg := tcpReadFrame(t, conn)
	if msg["type"] != "tasks" {
		t.Fatalf("tcp checkin did not deliver tasks: %+v", msg)
	}
	dataJSON, _ := json.Marshal(msg["data"])
	var claimed []struct {
		ID      string `json:"id"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(dataJSON, &claimed); err != nil || len(claimed) != 1 || claimed[0].ID != task.ID {
		t.Fatalf("tcp tasks payload mismatch: %s", dataJSON)
	}

	// Result -> ack
	tcpWriteFrame(t, conn, map[string]any{"type": "result", "data": map[string]any{
		"task_id": task.ID, "output": "legacy-tcp-result", "beacon_id": "legacy-tcp-id",
	}})
	ack = tcpReadFrame(t, conn)
	if ack["type"] != "ack" {
		t.Fatalf("tcp result ack: %+v", ack)
	}
	conn.Close()

	_, detail, _ = requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+task.ID, nil)
	_ = json.Unmarshal(detail.Data, &current)
	if current.Status != "completed" || current.Result != "legacy-tcp-result" {
		t.Fatalf("legacy tcp result not stored: %+v", current)
	}
}

// createLegacyTCPBeacon registers a TCP beacon over the unsigned protocol and
// returns the listener address.
func createLegacyTCPBeacon(t *testing.T, beaconID string) string {
	t.Helper()
	_, tcpAddr := createListenerType(t, "reverse_tcp")

	conn, err := net.DialTimeout("tcp", tcpAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tcpWriteFrame(t, conn, map[string]any{"type": "register", "data": map[string]any{
		"beacon_id": beaconID, "hostname": "host-" + beaconID, "username": "tester", "os": "linux", "sleep": 1, "jitter": 0,
	}})
	ack := tcpReadFrame(t, conn)
	if ack["type"] != "ack" {
		t.Fatalf("tcp register ack: %+v", ack)
	}
	return tcpAddr
}

func tcpWriteFrame(t *testing.T, conn net.Conn, msg any) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	length := uint32(len(data))
	header := []byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}
	if _, err := conn.Write(append(header, data...)); err != nil {
		t.Fatal(err)
	}
}

func tcpReadFrame(t *testing.T, conn net.Conn) map[string]any {
	t.Helper()
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	length := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("bad tcp frame: %v (%s)", err, data)
	}
	return msg
}

// TestBeaconAuthRequired verifies the HMAC gate with legacy compatibility
// disabled: unsigned, tampered and unknown-key requests must all be rejected.
func TestBeaconAuthRequired(t *testing.T) {
	setLegacyBeaconAuth(t, false)
	_, callbackURL := createListener(t)

	// Unsigned (legacy) request
	resp, err := http.Post(callbackURL, "application/json", strings.NewReader(`{"beacon_id":"ghost","hostname":"h"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned registration accepted with status %d", resp.StatusCode)
	}

	// Unsigned task poll (the old GET task-stealing vector)
	resp2, err := http.Get(callbackURL + "?id=ghost")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned GET poll returned %d, want 401", resp2.StatusCode)
	}

	// Bad signature
	_, key := createPayload(t, "auth-test-payload")
	body := []byte(`{"type":"poll"}`)
	ts, nonce, _ := beaconSignature(key, body)
	req, _ := http.NewRequest(http.MethodPost, callbackURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Beacon-ID", "ghost")
	req.Header.Set("X-Beacon-Timestamp", ts)
	req.Header.Set("X-Beacon-Nonce", nonce)
	req.Header.Set("X-Beacon-Sign", "deadbeef")
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad signature accepted with status %d", resp3.StatusCode)
	}
}

// TestFullSignedBeaconFlow exercises register -> task -> signed result.
func TestFullSignedBeaconFlow(t *testing.T) {
	_, callbackURL := createListener(t)
	_, key := createPayload(t, "flow-test-payload")
	registerBeacon(t, callbackURL, key, "flow-id")

	status, taskResponse, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/tasks", map[string]string{
		"client_id": "flow-id", "command": "echo integration",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create task: status=%d err=%v", status, err)
	}
	var task struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(taskResponse.Data, &task); err != nil || task.ID == "" {
		t.Fatalf("invalid task response: %s", taskResponse.Data)
	}

	tasks := pollBeaconTasks(t, callbackURL, key, "flow-id")
	if len(tasks) != 1 || tasks[0].ID != task.ID {
		t.Fatalf("expected claimed task %+v, got %+v", task.ID, tasks)
	}

	resp, err := submitBeaconResult(t, callbackURL, key, "flow-id", task.ID, "trusted")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submit result: status=%d", resp.StatusCode)
	}

	_, completedResponse, _ := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+task.ID, nil)
	var current struct{ Status, Result string }
	_ = json.Unmarshal(completedResponse.Data, &current)
	if current.Status != "completed" || current.Result != "trusted" {
		t.Fatalf("matching result was not stored: %+v", current)
	}
}

func TestMultipleBeaconsAndTaskResultIdentity(t *testing.T) {
	_, callbackURL := createListener(t)
	_, key := createPayload(t, "identity-test-payload")
	registerBeacon(t, callbackURL, key, "short-id")
	registerBeacon(t, callbackURL, key, "second-id")

	status, clientsResponse, err := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/clients", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("get clients: status=%d err=%v", status, err)
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(clientsResponse.Data, &clients); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, client := range clients {
		seen[client.ID] = true
	}
	if !seen["short-id"] || !seen["second-id"] {
		t.Fatalf("beacons were merged or missing: %+v", seen)
	}

	status, taskResponse, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/tasks", map[string]string{
		"client_id": "short-id", "command": "echo integration",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("create task: status=%d err=%v", status, err)
	}
	var task struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(taskResponse.Data, &task); err != nil || task.ID == "" {
		t.Fatalf("invalid task response: %s", taskResponse.Data)
	}

	tasks := pollBeaconTasks(t, callbackURL, key, "short-id")
	if len(tasks) == 0 {
		t.Fatal("expected pending task for short-id")
	}

	// A signed result bound to the WRONG beacon must not complete the task.
	resp, err := submitBeaconResult(t, callbackURL, key, "second-id", task.ID, "forged")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, currentResponse, err := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+task.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	var current struct{ Status, Result string }
	_ = json.Unmarshal(currentResponse.Data, &current)
	if current.Status != "running" || current.Result != "" {
		t.Fatalf("mismatched beacon completed task: %+v", current)
	}

	resp, err = submitBeaconResult(t, callbackURL, key, "short-id", task.ID, "trusted")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, completedResponse, _ := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+task.ID, nil)
	_ = json.Unmarshal(completedResponse.Data, &current)
	if current.Status != "completed" || current.Result != "trusted" {
		t.Fatalf("matching result was not stored: %+v", current)
	}
}

func TestFileManagerSecurityBoundaries(t *testing.T) {
	for _, body := range []map[string]any{
		{"file_name": "..", "total_size": 1, "total_chunks": 1},
		{"file_name": "ok.bin", "total_size": 0, "total_chunks": 1},
		{"file_name": "ok.bin", "total_size": int64(513 << 20), "total_chunks": 1},
	} {
		status, _, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/fm/upload/init", body)
		if err != nil || status != http.StatusBadRequest {
			t.Fatalf("invalid upload accepted: body=%+v status=%d err=%v", body, status, err)
		}
	}

	status, _, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/fm/mkdir", map[string]string{"path": "/rename-source"})
	if err != nil || status != http.StatusOK {
		t.Fatalf("mkdir: status=%d err=%v", status, err)
	}
	status, _, _ = requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/fm/rename", map[string]string{
		"old_path": "/rename-source", "new_name": "../escaped",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("path-bearing rename accepted with status %d", status)
	}

	// CSRF: state-changing API calls without the custom header are rejected.
	rawReq, _ := http.NewRequest(http.MethodPost, suite.baseURL+"/api/fm/mkdir", strings.NewReader(`{"path":"/csrf-test"}`))
	rawReq.Header.Set("Content-Type", "application/json")
	for _, cookie := range suite.client.Jar.Cookies(mustParse(suite.baseURL)) {
		rawReq.AddCookie(cookie)
	}
	rawResp, err := http.DefaultClient.Do(rawReq)
	if err != nil {
		t.Fatal(err)
	}
	rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF header accepted with status %d", rawResp.StatusCode)
	}

	outside, err := os.MkdirTemp("", "prtstrike-outside-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(suite.fmRoot, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	status, _, err = requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/fm/list?path="+url.QueryEscape("/link"), nil)
	if err != nil || status != http.StatusBadRequest {
		t.Fatalf("symlink escape accepted: status=%d err=%v", status, err)
	}
}

func mustParse(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}

func TestTunnelFeatureRemoved(t *testing.T) {
	targets := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/proxies"},
		{http.MethodPost, "/api/proxies"},
		{http.MethodDelete, "/api/proxies/legacy"},
		{http.MethodGet, "/static/modules/proxies.html"},
	}
	for _, target := range targets {
		req, err := http.NewRequest(target.method, suite.baseURL+target.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		resp, err := suite.client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", target.method, target.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s returned %d, want 404", target.method, target.path, resp.StatusCode)
		}
	}
}

func TestWebSocketOriginPolicy(t *testing.T) {
	base, _ := url.Parse(suite.baseURL)
	headers := http.Header{}
	for _, cookie := range suite.client.Jar.Cookies(base) {
		headers.Add("Cookie", cookie.String())
	}
	headers.Set("Origin", "https://evil.example")
	conn, response, err := websocket.DefaultDialer.Dial(suite.wsURL+"/ws", headers)
	if conn != nil {
		conn.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin websocket accepted: response=%v err=%v", response, err)
	}

	headers.Set("Origin", suite.baseURL)
	conn, response, err = websocket.DefaultDialer.Dial(suite.wsURL+"/ws", headers)
	if err != nil {
		t.Fatalf("same-origin websocket rejected: response=%v err=%v", response, err)
	}
	conn.Close()
}

func TestPayloadTemplatesContainAuthAndRuntimeID(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(suite.repoRoot, "implants", "beacon.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	if !strings.Contains(script, `BEACON_ID="$(generate_beacon_id)"`) {
		t.Fatal("bash payload does not generate its beacon ID at runtime")
	}
	if !strings.Contains(script, `\"beacon_id\":\"${BEACON_ID}\"`) {
		t.Fatal("bash payload does not bind results to its runtime beacon ID")
	}
	if !strings.Contains(script, "hmac_sign") || !strings.Contains(script, "{{BEACON_KEY}}") {
		t.Fatal("bash payload does not sign requests with the payload key")
	}

	py, err := os.ReadFile(filepath.Join(suite.repoRoot, "implants", "beacon.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(py), "hmac_mod.new(BEACON_KEY") || !strings.Contains(string(py), "{{BEACON_KEY}}") {
		t.Fatal("python payload does not sign requests with the payload key")
	}

	ps1, err := os.ReadFile(filepath.Join(suite.repoRoot, "implants", "beacon.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ps1), "HMACSHA256") || !strings.Contains(string(ps1), "{{BEACON_KEY}}") {
		t.Fatal("powershell payload does not sign requests with the payload key")
	}
}

func TestRemoteFileEditResultMapping(t *testing.T) {
	_, callbackURL := createListener(t)
	_, key := createPayload(t, "rfm-test-payload")
	registerBeacon(t, callbackURL, key, "rfm-client")

	tests := []struct {
		name       string
		result     string
		wantStatus int
	}{
		{"normal", `{"status":"ok","new_sha256":"newhash123"}`, http.StatusOK},
		{"conflict", `{"error":"CONFLICT","current_sha256":"actualhash123"}`, http.StatusConflict},
		{"permission", `{"error":"PERMISSION_DENIED"}`, http.StatusForbidden},
		{"oversized", `{"error":"FILE_TOO_LARGE"}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resultDone := make(chan error, 1)
			go func() {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					tasks := pollBeaconTasks(t, callbackURL, key, "rfm-client")
					if len(tasks) > 0 {
						resp, err := submitBeaconResult(t, callbackURL, key, "rfm-client", tasks[0].ID, test.result)
						if err != nil {
							resultDone <- err
							return
						}
						resp.Body.Close()
						resultDone <- nil
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				resultDone <- fmt.Errorf("timed out waiting for RFM task")
			}()

			status, _, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/rfm/edit", map[string]string{
				"client_id": "rfm-client", "path": "/tmp/test.txt", "content": "updated", "original_sha256": "oldhash",
			})
			if err != nil || status != test.wantStatus {
				t.Fatalf("RFM edit: status=%d want=%d err=%v", status, test.wantStatus, err)
			}
			if err := <-resultDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// ── Cluster ──────────────────────────────────────────────

type clusterNode struct {
	baseURL string
	client  *http.Client
	process *exec.Cmd
	logs    bytes.Buffer
}

// startClusterNode builds and boots an extra C2 node with its own data dir.
// extraEnv entries are appended to the node's environment (e.g. PRTS_NODE_ID).
func startClusterNode(t *testing.T, adminUser, adminPass string, extraEnv ...string) *clusterNode {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "prtstrike-cluster-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	executable := filepath.Join(tempDir, "prtstrike-"+adminUser+".exe")
	build := exec.Command("go", "build", "-o", executable, ".")
	build.Dir = suite.repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("node build failed: %v\n%s", err, output)
	}

	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	node := &clusterNode{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
	}
	jar, _ := cookiejar.New(nil)
	node.client = &http.Client{Jar: jar, Timeout: 15 * time.Second}
	node.process = exec.Command(executable)
	node.process.Dir = suite.repoRoot
	node.process.Env = append(append(os.Environ(), extraEnv...),
		fmt.Sprintf("PRTS_ADDR=127.0.0.1:%d", port),
		"PRTS_DB_PATH="+filepath.Join(tempDir, "node.db"),
		"PRTS_FM_ROOT="+filepath.Join(tempDir, "files"),
		"PRTS_SECRET=cluster-node-secret-with-length",
		"PRTS_ADMIN_USER="+adminUser,
		"PRTS_ADMIN_PASS="+adminPass,
	)
	node.process.Stdout = &node.logs
	node.process.Stderr = &node.logs
	if err := node.process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		node.process.Process.Kill()
		node.process.Process.Wait()
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := node.client.Get(node.baseURL + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Log in against the node's own URL.
	if err := loginTo(node.client, node.baseURL, adminUser, adminPass); err != nil {
		t.Fatalf("node login failed: %v\n%s", err, node.logs.String())
	}
	return node
}

// clusterSelfID returns a node's own cluster identity.
func clusterSelfID(t *testing.T, node *clusterNode) string {
	t.Helper()
	status, resp, err := requestJSON(node.client, http.MethodGet, node.baseURL+"/api/cluster/status", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("cluster status: status=%d err=%v", status, err)
	}
	var data struct {
		Self struct {
			ID string `json:"id"`
		} `json:"self"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil || data.Self.ID == "" {
		t.Fatalf("invalid cluster status: %s", resp.Data)
	}
	return data.Self.ID
}

// TestClusterTwoNodeSync joins a second node and verifies beacon replica
// sync plus cross-node task routing and result propagation.
func TestClusterTwoNodeSync(t *testing.T) {
	// Node A already runs as `suite`. Start node B.
	nodeB := startClusterNode(t, "nodeb-admin", "nodeb-password-2026")

	// A issues an invite; B joins with it.
	status, inviteResp, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/cluster/invite", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("invite: status=%d err=%v", status, err)
	}
	var invite struct {
		InviteToken string `json:"invite_token"`
	}
	if err := json.Unmarshal(inviteResp.Data, &invite); err != nil || invite.InviteToken == "" {
		t.Fatalf("invalid invite response: %s", inviteResp.Data)
	}

	status, joinResp, err := requestJSON(nodeB.client, http.MethodPost, nodeB.baseURL+"/api/cluster/join", map[string]string{
		"url": suite.baseURL, "invite_token": invite.InviteToken,
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("join: status=%d err=%v response=%+v", status, err, joinResp)
	}

	// Register a beacon on node A and wait for the replica on node B.
	_, callbackURL := createListener(t)
	_, key := createPayload(t, "cluster-test-payload")
	registerBeacon(t, callbackURL, key, "cluster-beacon")

	var replicaSeen bool
	for i := 0; i < 40; i++ {
		status, clientsResp, err := requestJSON(nodeB.client, http.MethodGet, nodeB.baseURL+"/api/clients", nil)
		if err == nil && status == http.StatusOK {
			var clients []struct {
				ID         string `json:"id"`
				HomeNodeID string `json:"home_node_id"`
			}
			if json.Unmarshal(clientsResp.Data, &clients) == nil {
				for _, c := range clients {
					if c.ID == "cluster-beacon" && c.HomeNodeID != "" && c.HomeNodeID != "00000000-0000-0000-0000-000000000000" {
						replicaSeen = true
					}
				}
			}
		}
		if replicaSeen {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !replicaSeen {
		t.Fatalf("beacon replica did not reach node B within timeout\nA logs:\n%s\nB logs:\n%s", suite.logs.String(), nodeB.logs.String())
	}

	// Operator on B tasks the beacon that lives on A.
	status, taskResp, err := requestJSON(nodeB.client, http.MethodPost, nodeB.baseURL+"/api/tasks", map[string]string{
		"client_id": "cluster-beacon", "command": "echo via-cluster",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("remote task create: status=%d err=%v", status, err)
	}
	var task struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(taskResp.Data, &task); err != nil || task.ID == "" {
		t.Fatalf("invalid task response: %s", taskResp.Data)
	}

	// Beacon polls node A (its home) and claims the forwarded task.
	var claimedID string
	for i := 0; i < 40; i++ {
		tasks := pollBeaconTasks(t, callbackURL, key, "cluster-beacon")
		if len(tasks) > 0 {
			claimedID = tasks[0].ID
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if claimedID == "" {
		t.Fatalf("forwarded task never reached node A\nA logs:\n%s\nB logs:\n%s", suite.logs.String(), nodeB.logs.String())
	}
	if claimedID != task.ID {
		t.Fatalf("forwarded task changed identity: %s != %s", claimedID, task.ID)
	}

	resp, err := submitBeaconResult(t, callbackURL, key, "cluster-beacon", claimedID, "cluster-result")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Origin node B must learn the result through cluster sync.
	var resultSeen bool
	for i := 0; i < 40; i++ {
		_, taskDetail, err := requestJSON(nodeB.client, http.MethodGet, nodeB.baseURL+"/api/tasks/"+task.ID, nil)
		if err == nil {
			var current struct{ Status, Result string }
			if json.Unmarshal(taskDetail.Data, &current) == nil && current.Status == "completed" && current.Result == "cluster-result" {
				resultSeen = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !resultSeen {
		t.Fatalf("task result did not propagate to origin node B\nA logs:\n%s\nB logs:\n%s", suite.logs.String(), nodeB.logs.String())
	}
}

// TestClusterDuplicateNodeIDRetry simulates a node deployed by copying
// another node's data directory (its stored node_id matches the inviter).
// The join must transparently regenerate the identity and succeed.
func TestClusterDuplicateNodeIDRetry(t *testing.T) {
	// Node A already runs as `suite`.
	selfID := clusterSelfID(t, &clusterNode{baseURL: suite.baseURL, client: suite.client})

	// Node B boots with A's identity (copied deployment).
	nodeB := startClusterNode(t, "dupnode-admin", "dupnode-password-2026",
		"PRTS_NODE_ID="+selfID)
	if got := clusterSelfID(t, nodeB); got != selfID {
		t.Fatalf("node B should boot with the duplicated id, got %s want %s", got, selfID)
	}

	status, inviteResp, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/cluster/invite", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("invite: status=%d err=%v", status, err)
	}
	var invite struct {
		InviteToken string `json:"invite_token"`
	}
	if err := json.Unmarshal(inviteResp.Data, &invite); err != nil || invite.InviteToken == "" {
		t.Fatalf("invalid invite response: %s", inviteResp.Data)
	}

	status, joinResp, err := requestJSON(nodeB.client, http.MethodPost, nodeB.baseURL+"/api/cluster/join", map[string]string{
		"url": suite.baseURL, "invite_token": invite.InviteToken,
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("join with duplicate id should self-heal: status=%d err=%v response=%+v\nB logs:\n%s", status, err, joinResp, nodeB.logs.String())
	}

	// B must now hold a fresh identity, different from A's.
	if got := clusterSelfID(t, nodeB); got == selfID {
		t.Fatal("node B kept the duplicated node id after join")
	}

	// And the two nodes must see each other as peers.
	var peerSeen bool
	for i := 0; i < 10; i++ {
		status, resp, err := requestJSON(nodeB.client, http.MethodGet, nodeB.baseURL+"/api/cluster/status", nil)
		if err == nil && status == http.StatusOK {
			var data struct {
				Peers []struct {
					ID     string `json:"id"`
					Status string `json:"status"`
				} `json:"peers"`
			}
			if json.Unmarshal(resp.Data, &data) == nil {
				for _, p := range data.Peers {
					if p.ID == selfID {
						peerSeen = true
					}
				}
			}
		}
		if peerSeen {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !peerSeen {
		t.Fatalf("node A not visible in B's peer list after join\nB logs:\n%s", nodeB.logs.String())
	}
}

// TestUninstallCommandDispatch verifies the uninstall endpoint queues an
// __UNINSTALL__ task that the beacon claims like any other command.
func TestUninstallCommandDispatch(t *testing.T) {
	_, callbackURL := createListener(t)
	_, key := createPayload(t, "uninstall-test-payload")
	registerBeacon(t, callbackURL, key, "uninstall-id")

	status, resp, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/clients/uninstall-id/uninstall", nil)
	if err != nil || status != http.StatusOK || resp.Message != "UNINSTALL_SENT" {
		t.Fatalf("uninstall dispatch: status=%d err=%v resp=%+v", status, err, resp)
	}

	// Beacon claims the uninstall command.
	tasks := pollBeaconTasks(t, callbackURL, key, "uninstall-id")
	if len(tasks) != 1 || tasks[0].Command != "__UNINSTALL__" {
		t.Fatalf("expected __UNINSTALL__ task, got %+v", tasks)
	}

	// Implant confirms; the result must land on the task record.
	httpResp, err := submitBeaconResult(t, callbackURL, key, "uninstall-id", tasks[0].ID, "UNINSTALLED")
	if err != nil {
		t.Fatal(err)
	}
	httpResp.Body.Close()

	_, detail, _ := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+tasks[0].ID, nil)
	var current struct{ Status, Result string }
	_ = json.Unmarshal(detail.Data, &current)
	if current.Status != "completed" || current.Result != "UNINSTALLED" {
		t.Fatalf("uninstall result not stored: %+v", current)
	}

	// Unknown beacon -> 404
	status, _, err = requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/clients/nope/uninstall", nil)
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("uninstall unknown beacon: status=%d err=%v", status, err)
	}
}
