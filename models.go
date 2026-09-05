package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func verifyPassword(stored, candidate string) (valid, needsUpgrade bool) {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) == nil, false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(candidate)) == 1, true
}

// ══════════════════════════════════════════════════════════
//  Data Models
// ══════════════════════════════════════════════════════════

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Username string `gorm:"uniqueIndex" json:"username"`
	Password string `json:"-"`
}

type Settings struct {
	ID               uint   `gorm:"primaryKey" json:"id"`
	ServerName       string `json:"server_name"`
	SessionTimeout   int    `json:"session_timeout"` // Hours
	Theme            string `json:"theme"`
	Debug            bool   `json:"debug"`
	GeoIPLookup      bool   `json:"geoip_lookup"`       // Third-party GeoIP enrichment (opsec-sensitive, default off)
	LegacyBeaconAuth bool   `json:"legacy_beacon_auth"` // Accept pre-HMAC (unsigned) beacon protocol; needed for old payloads, disable on fully re-issued fleets
}

// Client - Enhanced beacon information (CobaltStrike/Viper style)
type Client struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	IP          string    `json:"ip"`          // External IP (from RemoteAddr)
	InternalIP  string    `json:"internal_ip"` // Internal IP reported by beacon
	Status      string    `json:"status"`      // online, offline, dead
	OS          string    `json:"os"`          // e.g. "windows amd64", "linux amd64"
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	Domain      string    `json:"domain"`
	Arch        string    `json:"arch"`                      // x64, x86
	PID         int       `json:"pid"`                       // Beacon process PID
	ProcessName string    `json:"process_name"`              // Beacon process name
	IsAdmin     bool      `json:"is_admin"`                  // Elevated privileges
	ListenerID  string    `json:"listener_id"`               // Which listener it came from
	Note        string    `json:"note"`                      // Operator notes
	Group       string    `json:"group"`                     // Grouping tag
	HomeNodeID  string    `gorm:"index" json:"home_node_id"` // Cluster node owning this beacon
	FirstSeen   time.Time `json:"first_seen"`
	LastCheck   time.Time `json:"last_check"`
	Sleep       int       `json:"sleep"`
	Jitter      int       `json:"jitter"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
}

type Listener struct {
	ID          string       `gorm:"primaryKey" json:"id"`
	Name        string       `json:"name"`
	Type        string       `json:"type"` // reverse_http, reverse_https, reverse_tcp
	BindIP      string       `json:"bind_ip"`
	Port        int          `json:"port"`
	Status      string       `json:"status"`               // running, stopped
	NodeID      string       `gorm:"index" json:"node_id"` // Cluster node owning this listener
	server      *http.Server `gorm:"-"`
	tcpListener net.Listener `gorm:"-"`
}

// TCPMsg is the JSON envelope for TCP protocol messages.
// TS + Nonce + Sig carry the per-message HMAC-SHA256 authentication.
type TCPMsg struct {
	Type  string          `json:"type"` // register, checkin, result, tasks, sleep, ack, terminate
	Data  json.RawMessage `json:"data,omitempty"`
	TS    int64           `json:"ts,omitempty"`    // unix seconds
	Nonce string          `json:"nonce,omitempty"` // per-request nonce
	Sig   string          `json:"sig,omitempty"`   // hex HMAC(key, type + "." + ts + "." + nonce + "." + data)
}

type Payload struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // executable, powershell, shellcode_bin, shellcode_raw, python, bash
	OS          string    `json:"os"`   // windows, linux
	Arch        string    `json:"arch"` // amd64, 386
	FileSize    int64     `json:"file_size"`
	ListenerID  string    `json:"listener_id"`
	CreatedAt   time.Time `json:"created_at"`
	DownloadURL string    `json:"download_url"`
	BeaconKey   string    `json:"beacon_key"` // Per-payload HMAC key (hex); operator-visible for tooling/tests
}

// BeaconCredential binds a beacon ID to the payload key it authenticated with.
// The binding is created on the first signed registration, so payloads with a
// runtime-generated beacon ID (bash) still authenticate against their payload key.
type BeaconCredential struct {
	BeaconID  string    `gorm:"primaryKey" json:"beacon_id"`
	Key       string    `json:"key"`
	PayloadID string    `gorm:"index" json:"payload_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Task struct {
	ID         string    `gorm:"primaryKey" json:"id"`
	ClientID   string    `gorm:"index" json:"client_id"`
	Command    string    `json:"command"`
	Status     string    `json:"status"` // pending, running, completed, failed
	Result     string    `json:"result"`
	CreatedAt  time.Time `json:"created_at"`
	OriginNode string    `gorm:"index" json:"origin_node"` // Cluster node that issued the task
}

type ClusterNode struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`    // Base URL of the peer C2 API
	Token     string    `json:"-"`      // Pairwise HMAC token for this node pair
	Status    string    `json:"status"` // online, offline, self
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

// ClusterEvent is a persisted outbound event queue entry. Events are delivered
// to the target peer with retries; entries older than 24h are pruned.
type ClusterEvent struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	TargetNode string     `gorm:"index" json:"target_node"`
	Type       string     `json:"type"`
	Payload    string     `json:"payload"` // JSON body
	CreatedAt  time.Time  `json:"created_at"`
	SentAt     *time.Time `json:"sent_at"`
}

// KV stores small server-local state (local node identity, etc.)
type KV struct {
	Key   string `gorm:"primaryKey" json:"key"`
	Value string `json:"value"`
}

type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// CheckInData - JSON payload sent by enhanced beacon on check-in
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

type TaskResultData struct {
	TaskID   string `json:"task_id"`
	Output   string `json:"output"`
	BeaconID string `json:"beacon_id"`
}

// UploadSession - tracks a chunked upload in progress
type UploadSession struct {
	ID            string
	FileName      string
	DestPath      string // relative path within managed storage
	TotalSize     int64
	TotalChunks   int
	Received      map[int]bool
	ChunkSizes    map[int]int64
	ReceivedBytes int64
	Completed     bool
	TempDir       string
	CreatedAt     time.Time
	mu            sync.Mutex
}

// ══════════════════════════════════════════════════════════
//  Global Variables
// ══════════════════════════════════════════════════════════

var (
	db *gorm.DB

	// WebSocket: one writer pump per client so a slow browser can never
	// block the broadcast path. wsMutex only guards the map and the logs ring.
	wsClients = make(map[*wsClient]bool)
	wsMutex   sync.Mutex

	logs = make([]string, 0)

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil || u.Host == "" {
				return false
			}
			return strings.EqualFold(u.Host, r.Host) && (u.Scheme == "http" || u.Scheme == "https")
		},
	}

	// File Manager - upload sessions
	uploadSessions   = make(map[string]*UploadSession)
	uploadSessionsMu sync.Mutex

	// File Manager root
	fmRoot = envOrDefault("PRTS_FM_ROOT", "./files")
)

// wsClient wraps a websocket connection with an outbound buffered channel and
// a dedicated writer goroutine. shutdown() is idempotent.
type wsClient struct {
	conn *websocket.Conn
	send chan string
	once sync.Once
}

func (c *wsClient) shutdown() {
	c.once.Do(func() {
		wsMutex.Lock()
		delete(wsClients, c)
		wsMutex.Unlock()
		close(c.send)
		c.conn.Close()
	})
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

const credentialChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

func randomCredential(length int) string {
	out := make([]byte, length)
	max := big.NewInt(int64(len(credentialChars)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			log.Fatal("failed to generate random credential:", err)
		}
		out[i] = credentialChars[n.Int64()]
	}
	return string(out)
}

func randomHexKey(bytesLen int) string {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		log.Fatal("failed to generate random key:", err)
	}
	return hex.EncodeToString(b)
}

func kvGet(key string) (string, bool) {
	var row KV
	if err := db.First(&row, "key = ?", key).Error; err != nil {
		return "", false
	}
	return row.Value, true
}

func kvSet(key, value string) {
	db.Save(&KV{Key: key, Value: value})
}

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open(envOrDefault("PRTS_DB_PATH", "prts_c2.db")), &gorm.Config{
		// Explicit db.Transaction calls remain transactional. Independent
		// single-statement writes no longer pay for an extra BEGIN/COMMIT pair.
		SkipDefaultTransaction: true,
	})
	if err != nil {
		log.Fatal("failed to connect database:", err)
	}

	// Auto Migrate all models
	err = db.AutoMigrate(
		&User{}, &Client{}, &Listener{}, &Payload{},
		&Task{}, &Settings{}, &BeaconCredential{},
		&ClusterNode{}, &ClusterEvent{}, &KV{},
	)
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}

	// Upgrades add the legacy-compat column as NULL for existing rows; flip
	// those to enabled so pre-HMAC payloads keep connecting after the update.
	db.Model(&Settings{}).Where("legacy_beacon_auth IS NULL").Update("legacy_beacon_auth", true)

	// Local cluster node identity (PRTS_NODE_ID pins it explicitly)
	if _, ok := kvGet("node_id"); !ok {
		id := strings.TrimSpace(os.Getenv("PRTS_NODE_ID"))
		if id == "" {
			id = uuid.NewString()
		}
		kvSet("node_id", id)
	}

	// Create initial user if none exists. The password is taken from
	// PRTS_ADMIN_PASS, or generated randomly and written (mode 0600) to
	// admin_credentials.txt next to the database. No fixed default exists.
	var count int64
	db.Model(&User{}).Count(&count)
	if count == 0 {
		username := envOrDefault("PRTS_ADMIN_USER", "prtadmin")
		password := os.Getenv("PRTS_ADMIN_PASS")
		if password == "" {
			password = randomCredential(18)
			credsFile := envOrDefault("PRTS_CREDENTIALS_FILE", "admin_credentials.txt")
			content := fmt.Sprintf("PRTSTRIKE initial credentials (rotate after first login)\nusername: %s\npassword: %s\n", username, password)
			if err := os.WriteFile(credsFile, []byte(content), 0600); err != nil {
				log.Printf("[!] Could not write %s: %v", credsFile, err)
			} else {
				log.Printf("[+] Initial credentials written to %s", credsFile)
			}
		}
		passwordHash, hashErr := hashPassword(password)
		if hashErr != nil {
			log.Fatal("failed to hash initial password:", hashErr)
		}
		if err := db.Create(&User{Username: username, Password: passwordHash}).Error; err != nil {
			log.Fatal("failed to create initial user:", err)
		}
		log.Printf("[+] Initial operator account %q created.", username)
	}

	// Create Default Settings if not exists
	var settingsCount int64
	db.Model(&Settings{}).Count(&settingsCount)
	if settingsCount == 0 {
		db.Create(&Settings{
			ServerName:       "PRTSTRIKE",
			SessionTimeout:   24,
			Theme:            "PRTSTRIKE_DARK",
			Debug:            false,
			GeoIPLookup:      false,
			LegacyBeaconAuth: true,
		})
		log.Println("[INFO] Default settings created.")
	}
}
