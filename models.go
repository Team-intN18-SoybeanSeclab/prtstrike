package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
)

// --- Structs ---

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Username string `gorm:"uniqueIndex" json:"username"`
	Password string `json:"-"`
}

type Settings struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	ServerName     string `json:"server_name"`
	SessionTimeout int    `json:"session_timeout"` // Hours
	Theme          string `json:"theme"`
	Debug          bool   `json:"debug"`
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
	Arch        string    `json:"arch"`         // x64, x86
	PID         int       `json:"pid"`          // Beacon process PID
	ProcessName string    `json:"process_name"` // Beacon process name
	IsAdmin     bool      `json:"is_admin"`     // Elevated privileges
	ListenerID  string    `json:"listener_id"`  // Which listener it came from
	Note        string    `json:"note"`         // Operator notes
	Group       string    `json:"group"`        // Grouping tag
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
	Status      string       `json:"status"` // running, stopped
	server      *http.Server `gorm:"-"`
	tcpListener net.Listener `gorm:"-"`
}

// TCPMsg is the JSON envelope for TCP protocol messages
type TCPMsg struct {
	Type string          `json:"type"` // register, checkin, result, tasks, sleep, ack
	Data json.RawMessage `json:"data,omitempty"`
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
}

type Task struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	ClientID  string    `gorm:"index" json:"client_id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"` // pending, running, completed, failed
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}

type Proxy struct {
	ID         string    `gorm:"primaryKey" json:"id"`
	ClientID   string    `gorm:"index" json:"client_id"`
	Type       string    `json:"type"` // chisel_reverse, chisel_forward, chisel_socks
	Mode       string    `json:"mode"` // server, client
	ListenPort int       `json:"listen_port"`
	RemoteStr  string    `json:"remote_str"` // chisel remote spec e.g. "R:socks" or "R:8080:10.0.0.1:80"
	ServerURL  string    `json:"server_url"` // chisel server URL for client connections
	AuthKey    string    `json:"auth_key"`
	WsPath     string    `json:"ws_path"` // randomized websocket path
	Status     string    `json:"status"`
	PID        int       `json:"pid"`
	CreatedAt  time.Time `json:"created_at"`
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

// UploadSession - tracks a chunked upload in progress
type UploadSession struct {
	ID          string
	FileName    string
	DestPath    string // relative path within managed storage
	TotalSize   int64
	TotalChunks int
	Received    map[int]bool
	TempDir     string
	CreatedAt   time.Time
}

// --- Global Variables ---

var (
	db *gorm.DB

	// WebSocket Globals
	wsClients   = make(map[*websocket.Conn]bool)
	wsBroadcast = make(chan string, 256)
	wsMutex     sync.Mutex

	logs = make([]string, 0)

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	// File Manager - upload sessions
	uploadSessions   = make(map[string]*UploadSession)
	uploadSessionsMu sync.Mutex

	// File Manager root
	fmRoot = "./files"
)

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("prts_c2.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database:", err)
	}

	// Auto Migrate all models
	err = db.AutoMigrate(
		&User{}, &Client{}, &Listener{}, &Payload{},
		&Task{}, &Proxy{}, &Settings{},
	)
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}

	// Create Default User if not exists
	var count int64
	db.Model(&User{}).Count(&count)
	if count == 0 {
		db.Create(&User{Username: "Adm1nstr@t0r", Password: "Pr3c1se5!@#$%"})
		log.Println("[INFO] Default users 'Adm1nstr@t0r' created.")
	}

	// Create Default Settings if not exists
	var settingsCount int64
	db.Model(&Settings{}).Count(&settingsCount)
	if settingsCount == 0 {
		db.Create(&Settings{
			ServerName:     "PRTSTRIKE",
			SessionTimeout: 24,
			Theme:          "PRTSTRIKE_DARK",
			Debug:          false,
		})
		log.Println("[INFO] Default settings created.")
	}
}
