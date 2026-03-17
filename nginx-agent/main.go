// nginx-agent is a lightweight HTTP sidecar that runs alongside nginx.
// edgepanel (the server) sends the fully-rendered nginx config files to
// this agent via POST /apply; the agent writes the files atomically, runs
// `nginx -t` to validate them, and then `nginx -s reload` to activate them.
// This decouples the edgepanel control plane from the nginx data plane,
// removing the need for a shared Docker socket or shared config volume.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// applyRequest is the JSON body accepted by POST /apply.
// Files is a map of relative config path → file content.
// All paths are joined against ConfigDir on the agent side.
type applyRequest struct {
	Files map[string]string `json:"files"`
}

// applyResponse is the JSON body returned by POST /apply.
type applyResponse struct {
	Message string `json:"message,omitempty"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	configDir := getEnv("CONFIG_DIR", "/etc/nginx/conf.d/generated")
	nginxBinary := getEnv("NGINX_BINARY", "/usr/sbin/nginx")
	agentToken := getEnv("AGENT_TOKEN", "")
	agentPort := getEnv("AGENT_PORT", "9090")

	a := &agent{
		configDir:   configDir,
		nginxBinary: nginxBinary,
		agentToken:  agentToken,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.healthHandler)
	mux.HandleFunc("/apply", a.applyHandler)

	srv := &http.Server{
		Addr:         ":" + agentPort,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("nginx-agent listening on :%s (config dir: %s, nginx: %s)", agentPort, configDir, nginxBinary)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("nginx-agent: %v", err)
		}
	}()

	// Graceful shutdown on SIGTERM / SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit
	log.Println("nginx-agent: shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("nginx-agent: shutdown error: %v", err)
	}
	log.Println("nginx-agent: stopped")
}

// agent holds the runtime configuration for the HTTP handler methods.
type agent struct {
	configDir   string
	nginxBinary string
	agentToken  string
}

// checkToken validates the Authorization header when a token is configured.
func (a *agent) checkToken(r *http.Request) bool {
	if a.agentToken == "" {
		return true // authentication not configured
	}
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return token == a.agentToken
}

// healthHandler responds to GET /health with a simple JSON status.
func (a *agent) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// applyHandler handles POST /apply.
// It validates auth, writes config files, runs nginx -t, then nginx -s reload.
func (a *agent) applyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req applyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Atomically write all config files.
	if err := a.writeFiles(req.Files); err != nil {
		writeJSON(w, http.StatusInternalServerError, applyResponse{
			Error: fmt.Sprintf("failed to write config files: %v", err),
		})
		return
	}

	// Test the new config.
	testOut, err := a.execNginx("-t")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, applyResponse{
			Error:  "nginx config test failed",
			Output: testOut,
		})
		return
	}

	// Reload nginx to pick up the new config.
	reloadOut, err := a.execNginx("-s", "reload")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, applyResponse{
			Error:  "nginx reload failed",
			Output: reloadOut,
		})
		return
	}

	writeJSON(w, http.StatusOK, applyResponse{
		Message: "nginx config applied and reloaded",
		Output:  testOut + reloadOut,
	})
}

// writeFiles writes each file in the map atomically under a.configDir.
// Relative subdirectories (e.g. "routes/", "iplists/") are created as needed.
func (a *agent) writeFiles(files map[string]string) error {
	for relPath, content := range files {
		absPath := filepath.Join(a.configDir, relPath)
		dir := filepath.Dir(absPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		tmp := absPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
			return fmt.Errorf("write tmp %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, absPath); err != nil {
			return fmt.Errorf("rename %s → %s: %w", tmp, absPath, err)
		}
	}
	return nil
}

// execNginx runs the nginx binary with the given arguments and returns combined output.
func (a *agent) execNginx(args ...string) (string, error) {
	cmd := exec.Command(a.nginxBinary, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// writeJSON encodes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
