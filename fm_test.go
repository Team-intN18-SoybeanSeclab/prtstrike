package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupRFMTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	// Initialize in-memory SQLite for testing
	db, _ = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	db.AutoMigrate(&Client{}, &Task{})

	// Add dummy online client
	db.Create(&Client{
		ID:     "test-client-123",
		Status: "online",
		Sleep:  1,
		Jitter: 0,
	})

	r.POST("/api/rfm/edit", handleRemoteFMEdit)
	return r
}

func mockBeaconTaskProcessor(t *testing.T, expectedResponse string) {
	go func() {
		for i := 0; i < 50; i++ {
			time.Sleep(10 * time.Millisecond)
			var task Task
			if err := db.Where("status = ?", "pending").First(&task).Error; err == nil {
				// Mark as running then completed
				task.Status = "completed"
				task.Result = expectedResponse
				db.Save(&task)
				return
			}
		}
	}()
}

func TestHandleRemoteFMEdit_Normal(t *testing.T) {
	router := setupRFMTestRouter()

	mockBeaconTaskProcessor(t, `{"status":"ok","new_sha256":"newhash123"}`)

	reqBody, _ := json.Marshal(map[string]string{
		"client_id":       "test-client-123",
		"path":            "/tmp/test.txt",
		"content":         "Updated Content",
		"original_sha256": "oldhash123",
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/rfm/edit", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "success", resp.Status)
	data := resp.Data.(map[string]interface{})
	assert.Equal(t, "newhash123", data["new_sha256"])
}

func TestHandleRemoteFMEdit_Conflict(t *testing.T) {
	router := setupRFMTestRouter()

	mockBeaconTaskProcessor(t, `{"error":"CONFLICT","current_sha256":"actualhash123"}`)

	reqBody, _ := json.Marshal(map[string]string{
		"client_id":       "test-client-123",
		"path":            "/tmp/conflict.txt",
		"content":         "Conflict Attempt",
		"original_sha256": "wronghash",
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/rfm/edit", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "error", resp.Status)
	data := resp.Data.(map[string]interface{})
	assert.Equal(t, "actualhash123", data["current_sha256"])
}

func TestHandleRemoteFMEdit_PermissionDenied(t *testing.T) {
	router := setupRFMTestRouter()

	mockBeaconTaskProcessor(t, `{"error":"PERMISSION_DENIED"}`)

	reqBody, _ := json.Marshal(map[string]string{
		"client_id":       "test-client-123",
		"path":            "/etc/passwd",
		"content":         "hacked",
		"original_sha256": "hash",
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/rfm/edit", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleRemoteFMEdit_Oversized(t *testing.T) {
	router := setupRFMTestRouter()

	mockBeaconTaskProcessor(t, `{"error":"FILE_TOO_LARGE"}`)

	reqBody, _ := json.Marshal(map[string]string{
		"client_id":       "test-client-123",
		"path":            "/tmp/large.txt",
		"content":         "too big",
		"original_sha256": "hash",
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/rfm/edit", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp APIResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "FILE_TOO_LARGE", resp.Message)
}
