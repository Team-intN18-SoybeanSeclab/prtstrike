package integration_test

import (
	"bytes"
	"context"
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
				return s.login(s.client, "Adm1nstr@t0r", "Pr3c1se5!@#$%")
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
	resp, err := client.PostForm(s.baseURL+"/api/login", url.Values{
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

func createListener(t *testing.T) (string, string) {
	t.Helper()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	status, response, err := requestJSON(suite.client, http.MethodPost, suite.baseURL+"/api/listeners", map[string]any{
		"name": "integration", "type": "reverse_http", "bind_ip": "127.0.0.1", "port": port,
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
	return listener.ID, fmt.Sprintf("http://127.0.0.1:%d/checkin", port)
}

func registerBeacon(t *testing.T, callbackURL, id string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"beacon_id": id, "hostname": "host-" + id, "username": "tester", "os": "linux", "sleep": 1, "jitter": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, callbackURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("register beacon %q: status=%d body=%s", id, resp.StatusCode, data)
	}
}

func TestAuthenticationAndPasswordChange(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if err := suite.login(client, "Adm1nstr@t0r", "wrong-password"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	if err := suite.login(client, "Adm1nstr@t0r", "Pr3c1se5!@#$%"); err != nil {
		t.Fatal(err)
	}
	newPassword := "integration-password-2026"
	status, _, err := requestJSON(client, http.MethodPost, suite.baseURL+"/api/change-password", map[string]string{
		"old_password": "Pr3c1se5!@#$%", "new_password": newPassword,
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("change password: status=%d err=%v", status, err)
	}
	newJar, _ := cookiejar.New(nil)
	newClient := &http.Client{Jar: newJar, Timeout: 10 * time.Second}
	if err := suite.login(newClient, "Adm1nstr@t0r", "Pr3c1se5!@#$%"); err == nil {
		t.Fatal("old password remained valid")
	}
	if err := suite.login(newClient, "Adm1nstr@t0r", newPassword); err != nil {
		t.Fatal(err)
	}
	status, _, err = requestJSON(newClient, http.MethodPost, suite.baseURL+"/api/change-password", map[string]string{
		"old_password": newPassword, "new_password": "Pr3c1se5!@#$%",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("restore password: status=%d err=%v", status, err)
	}
}

func TestMultipleBeaconsAndTaskResultIdentity(t *testing.T) {
	_, callbackURL := createListener(t)
	registerBeacon(t, callbackURL, "short-id")
	registerBeacon(t, callbackURL, "second-id")

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

	req, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
	req.Header.Set("X-Beacon-ID", "short-id")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	status, _, err = requestJSON(http.DefaultClient, http.MethodPost, callbackURL, map[string]string{
		"task_id": task.ID, "output": "forged", "beacon_id": "second-id",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("submit mismatched result: status=%d err=%v", status, err)
	}
	_, currentResponse, err := requestJSON(suite.client, http.MethodGet, suite.baseURL+"/api/tasks/"+task.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	var current struct{ Status, Result string }
	_ = json.Unmarshal(currentResponse.Data, &current)
	if current.Status != "running" || current.Result != "" {
		t.Fatalf("mismatched beacon completed task: %+v", current)
	}

	_, _, err = requestJSON(http.DefaultClient, http.MethodPost, callbackURL, map[string]string{
		"task_id": task.ID, "output": "trusted", "beacon_id": "short-id",
	})
	if err != nil {
		t.Fatal(err)
	}
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

func TestBashPayloadUsesRuntimeBeaconID(t *testing.T) {
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
}

func TestRemoteFileEditResultMapping(t *testing.T) {
	_, callbackURL := createListener(t)
	registerBeacon(t, callbackURL, "rfm-client")

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
					req, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
					req.Header.Set("X-Beacon-ID", "rfm-client")
					resp, err := http.DefaultClient.Do(req)
					if err == nil {
						var tasks []struct {
							ID string `json:"id"`
						}
						decodeErr := json.NewDecoder(resp.Body).Decode(&tasks)
						resp.Body.Close()
						if decodeErr == nil && len(tasks) > 0 {
							_, _, postErr := requestJSON(http.DefaultClient, http.MethodPost, callbackURL, map[string]string{
								"task_id": tasks[0].ID, "output": test.result, "beacon_id": "rfm-client",
							})
							resultDone <- postErr
							return
						}
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
