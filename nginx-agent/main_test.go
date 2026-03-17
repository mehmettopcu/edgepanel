package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestAgent(t *testing.T) (*agent, string) {
	t.Helper()
	dir := t.TempDir()
	return &agent{
		configDir:   dir,
		nginxBinary: "nginx", // not invoked in file-write tests
		agentToken:  "",
	}, dir
}

// ---------------------------------------------------------------------------
// healthHandler
// ---------------------------------------------------------------------------

func TestHealthHandler_ReturnsOK(t *testing.T) {
	a, _ := newTestAgent(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	a.healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", resp["status"])
	}
}

func TestHealthHandler_MethodNotAllowed(t *testing.T) {
	a, _ := newTestAgent(t)
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	a.healthHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// writeFiles
// ---------------------------------------------------------------------------

func TestWriteFiles_CreatesFiles(t *testing.T) {
	a, dir := newTestAgent(t)
	files := map[string]string{
		"routes/1.conf":    "server {}",
		"iplists/1.allow":  "allow 10.0.0.1;\n",
		"iplists/1.deny":   "",
		"waf.conf":         "# waf\n",
	}
	if err := a.writeFiles(files); err != nil {
		t.Fatalf("writeFiles: %v", err)
	}
	for rel, want := range files {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Errorf("file %s not found: %v", rel, err)
			continue
		}
		if string(data) != want {
			t.Errorf("file %s: want %q, got %q", rel, want, string(data))
		}
	}
}

// ---------------------------------------------------------------------------
// checkToken
// ---------------------------------------------------------------------------

func TestCheckToken_NoTokenConfigured(t *testing.T) {
	a := &agent{agentToken: ""}
	req := httptest.NewRequest(http.MethodPost, "/apply", nil)
	if !a.checkToken(req) {
		t.Error("checkToken should return true when no token is configured")
	}
}

func TestCheckToken_ValidToken(t *testing.T) {
	a := &agent{agentToken: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/apply", nil)
	req.Header.Set("Authorization", "Bearer secret")
	if !a.checkToken(req) {
		t.Error("checkToken should return true for correct token")
	}
}

func TestCheckToken_InvalidToken(t *testing.T) {
	a := &agent{agentToken: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/apply", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	if a.checkToken(req) {
		t.Error("checkToken should return false for wrong token")
	}
}

func TestCheckToken_MissingHeader(t *testing.T) {
	a := &agent{agentToken: "secret"}
	req := httptest.NewRequest(http.MethodPost, "/apply", nil)
	if a.checkToken(req) {
		t.Error("checkToken should return false when Authorization header is missing")
	}
}

// ---------------------------------------------------------------------------
// applyHandler — file-write path (nginx binary not invoked)
// ---------------------------------------------------------------------------

func TestApplyHandler_UnauthorizedWhenTokenMismatch(t *testing.T) {
	a := &agent{agentToken: "secret"}
	body := strings.NewReader(`{"files": {}}`)
	req := httptest.NewRequest(http.MethodPost, "/apply", body)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	a.applyHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestApplyHandler_BadJSON(t *testing.T) {
	a, _ := newTestAgent(t)
	req := httptest.NewRequest(http.MethodPost, "/apply", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	a.applyHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestApplyHandler_MethodNotAllowed(t *testing.T) {
	a, _ := newTestAgent(t)
	req := httptest.NewRequest(http.MethodGet, "/apply", nil)
	w := httptest.NewRecorder()
	a.applyHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
