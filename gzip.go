package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// gzipWriterPool reuses compressors: allocation dominates the cost of
// compressing the many small text responses the dashboard produces.
var gzipWriterPool = sync.Pool{
	New: func() any {
		w, err := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		if err != nil {
			panic(err)
		}
		return w
	},
}

// gzipResponseWriter routes the body through a gzip compressor when the
// response is text. The decision is made as late as possible: handlers set
// Content-Type at different points (http.ServeContent before WriteHeader, the
// gin JSON renderer only moments before the first body write).
type gzipResponseWriter struct {
	gin.ResponseWriter
	gz      *gzip.Writer
	decided bool // content type inspected
	started bool // body bytes flow through the compressor
}

func (w *gzipResponseWriter) evaluate() {
	if w.decided {
		return
	}
	ct := w.Header().Get("Content-Type")
	if ct == "" {
		return
	}
	w.decided = true
	switch w.ResponseWriter.Status() {
	case http.StatusNoContent, http.StatusNotModified:
		return // no body to compress
	}
	if !compressibleContentType(ct) || w.Header().Get("Content-Encoding") != "" {
		return
	}
	// The advertised length is now meaningless and would truncate the
	// decoded body at the client.
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	w.gz.Reset(w.ResponseWriter)
	w.started = true
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	w.evaluate()
	// gin buffers the status code; flush it together with our headers before
	// the first body byte reaches the wire.
	w.ResponseWriter.WriteHeaderNow()
	if w.started {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	w.evaluate()
	w.ResponseWriter.WriteHeader(code)
}

// gzipMiddleware compresses text responses for browser clients. Binary
// payloads, range requests, the websocket and anything not accepting gzip
// pass through untouched; beacon traffic never uses this engine.
func gzipMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet ||
			c.Request.Header.Get("Range") != "" ||
			strings.HasPrefix(c.Request.URL.Path, "/ws") ||
			strings.HasPrefix(c.Request.URL.Path, "/static/payloads/") ||
			!acceptsGzip(c.GetHeader("Accept-Encoding")) {
			c.Next()
			return
		}
		gz := gzipWriterPool.Get().(*gzip.Writer)
		c.Writer = &gzipResponseWriter{ResponseWriter: c.Writer, gz: gz}
		c.Next()
		if w, ok := c.Writer.(*gzipResponseWriter); ok && w.started {
			_ = gz.Close()
		}
		gzipWriterPool.Put(gz)
	}
}

func acceptsGzip(header string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		token := strings.TrimSpace(part)
		if token != "gzip" && !strings.HasPrefix(token, "gzip;") {
			continue
		}
		// Honour an explicit refusal (q=0).
		if i := strings.Index(token, "q="); i >= 0 && strings.TrimSpace(token[i+2:]) == "0" {
			return false
		}
		return true
	}
	return false
}

func compressibleContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch strings.TrimSpace(ct) {
	case "text/html", "text/css", "text/plain", "text/xml", "text/javascript",
		"application/json", "application/javascript", "application/x-javascript",
		"application/xml", "image/svg+xml", "application/manifest+json":
		return true
	default:
		return false
	}
}
