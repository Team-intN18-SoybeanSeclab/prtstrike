package main

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	// Avoid the formatting and stdout I/O cost of an access log for every
	// request in normal operation. Debug mode can opt back into it.
	r := gin.New()
	settingsMutex.RLock()
	debug := GlobalSettings.Debug
	settingsMutex.RUnlock()
	if debug {
		r.Use(gin.Logger())
	}
	r.Use(gin.Recovery())

	// Session secret: prefer env var, otherwise generate random key each startup
	secretKey := os.Getenv("PRTS_SECRET")
	if secretKey == "" {
		b := make([]byte, 32)
		if _, err := cryptoRand.Read(b); err != nil {
			log.Fatal("Failed to generate session secret:", err)
		}
		secretKey = hex.EncodeToString(b)
	}
	store := cookie.NewStore([]byte(secretKey))
	r.Use(sessions.Sessions("prts-session", store))

	// Session Timeout Middleware
	r.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		settingsMutex.RLock()
		timeout := GlobalSettings.SessionTimeout
		settingsMutex.RUnlock()

		if timeout > 0 {
			session.Options(sessions.Options{
				Path:     "/",
				MaxAge:   timeout * 3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
		c.Next()
	})

	// Static files: protect /static/payloads/ behind auth, serve rest normally
	r.GET("/static/*filepath", func(c *gin.Context) {
		p := c.Param("filepath")
		filePath, relPath, ok := staticFilePath(p)
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
		if relPath == "payloads" || strings.HasPrefix(relPath, "payloads"+string(filepath.Separator)) {
			// Require authentication for payload downloads
			session := sessions.Default(c)
			if auth := session.Get("authenticated"); auth != true {
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "UNAUTHORIZED"})
				c.Abort()
				return
			}
		}
		c.File(filePath)
	})

	r.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		if auth := session.Get("authenticated"); auth == true {
			c.Redirect(http.StatusSeeOther, "/dashboard")
			return
		}
		c.File("./static/index.html")
	})

	r.GET("/dashboard", AuthRequired(), func(c *gin.Context) {
		c.File("./static/dashboard.html")
	})

	// API Routes
	api := r.Group("/api")
	{
		api.POST("/login", handleLogin)
		api.GET("/logout", handleLogout)

		auth := api.Group("/")
		auth.Use(AuthRequired())
		{
			auth.GET("/userinfo", handleGetUserInfo)

			// Client routes
			auth.GET("/clients", handleGetClients)
			auth.GET("/clients/:id", handleGetClientDetail)
			auth.PUT("/clients/:id", handleUpdateClientNote)
			auth.DELETE("/clients/:id", handleDeleteClient)
			auth.POST("/clients/:id/kill", handleKillBeacon)

			// Listener routes
			auth.GET("/listeners", handleGetListeners)
			auth.POST("/listeners", handleCreateListener)
			auth.POST("/listeners/:id/start", handleStartListener)
			auth.POST("/listeners/:id/stop", handleStopListener)
			auth.DELETE("/listeners/:id", handleDeleteListener)

			// Payload routes
			auth.GET("/payloads", handleGetPayloads)
			auth.POST("/payloads", handleGeneratePayload)
			auth.DELETE("/payloads/:id", handleDeletePayload)

			// Task routes
			auth.GET("/tasks", handleGetTasks)
			auth.GET("/tasks/:id", handleGetTask)
			auth.POST("/tasks", handleCreateTask)

			// File routes
			auth.GET("/files", handleGetFiles)
			auth.POST("/upload", handleFileUpload)

			// File Manager routes (local server files)
			fm := auth.Group("/fm")
			{
				fm.GET("/list", handleFMList)
				fm.POST("/mkdir", handleFMMkdir)
				fm.POST("/rename", handleFMRename)
				fm.POST("/delete", handleFMDelete)
				fm.POST("/upload/init", handleFMUploadInit)
				fm.POST("/upload/chunk/:upload_id", handleFMUploadChunk)
				fm.POST("/upload/complete/:upload_id", handleFMUploadComplete)
				fm.GET("/download", handleFMDownload)
				fm.GET("/info", handleFMInfo)
			}

			// Remote File Manager routes (beacon/controlled host files)
			rfm := auth.Group("/rfm")
			{
				rfm.GET("/list", handleRemoteFMList)
				rfm.GET("/download", handleRemoteFMDownload)
				rfm.POST("/upload", handleRemoteFMUpload)
				rfm.POST("/mkdir", handleRemoteFMMkdir)
				rfm.POST("/delete", handleRemoteFMDelete)
				rfm.POST("/edit", handleRemoteFMEdit)
			}

			// System routes
			auth.GET("/processes", handleGetProcesses)
			auth.GET("/screenshot", handleGetScreenshot)
			auth.GET("/stats", handleGetStats)
			auth.GET("/logs", handleGetLogs)
			auth.GET("/settings", handleGetSettings)
			auth.POST("/settings", handleSaveSettings)
			auth.POST("/change-password", handleChangePassword)
			auth.POST("/quick-command", handleQuickCommand)

			// Callback filter routes
			auth.GET("/filters", handleGetFilters)
			auth.POST("/filters", handleUpdateFilters)
		}
	}

	// WebSocket (requires authentication)
	r.GET("/ws", AuthRequired(), handleWS)

	addr := envOrDefault("PRTS_ADDR", ":8083")
	fmt.Printf("[+] PRTSTRIKE C2 SERVER (GIN) STARTED ON %s\n", addr)
	log.Fatal(r.Run(addr))
}

// staticFilePath resolves a wildcard URL path under ./static without allowing
// traversal into the working directory or an absolute filesystem path.
func staticFilePath(requestPath string) (filePath, relativePath string, ok bool) {
	relativePath = strings.TrimLeft(requestPath, "/\\")
	relativePath = filepath.Clean(relativePath)
	if relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) || filepath.IsAbs(relativePath) {
		return "", "", false
	}
	root, err := filepath.Abs("./static")
	if err != nil {
		return "", "", false
	}
	filePath = filepath.Join(root, relativePath)
	resolved, err := filepath.Abs(filePath)
	if err != nil || (resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator))) {
		return "", "", false
	}
	if !staticPathWithinRoot(resolved, root) {
		return "", "", false
	}
	return resolved, relativePath, true
}

func staticPathWithinRoot(path, root string) bool {
	probe := path
	for {
		if linked, err := filepath.EvalSymlinks(probe); err == nil {
			linked, _ = filepath.Abs(linked)
			return linked == root || strings.HasPrefix(linked, root+string(filepath.Separator))
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return false
		}
		probe = parent
	}
}
