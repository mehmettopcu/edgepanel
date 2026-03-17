package nginx_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mehmettopcu/edgepanel/internal/models"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
)

// ---------------------------------------------------------------------------
// Agent path: GenerateAndTest delegates to nginx-agent HTTP API
// ---------------------------------------------------------------------------

// agentApplyRequest mirrors the struct in client.go for test assertions.
type agentApplyRequest struct {
	Files map[string]string `json:"files"`
}

// newAgentGenerator creates a Generator wired to the given mock agent server URL.
func newAgentGenerator(t *testing.T, agentURL string) *nginx.Generator {
	t.Helper()
	dir := t.TempDir()
	gen := nginx.New(dir, "nginx")
	gen.AgentURL = agentURL
	return gen
}

func TestGenerateAndTest_AgentMode_SendsFilesToAgent(t *testing.T) {
	var received agentApplyRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/apply" {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "nginx config applied and reloaded",
			"output":  "ok",
		})
	}))
	defer srv.Close()

	gen := newAgentGenerator(t, srv.URL)
	routes := []*models.Route{validRoute(1)}
	out, err := gen.GenerateAndTest(routes, defaultSettings())
	if err != nil {
		t.Fatalf("GenerateAndTest via agent: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output from agent")
	}

	// Verify the agent received the expected file keys.
	expectedKeys := []string{"routes/1.conf", "iplists/1.allow", "iplists/1.deny", "waf.conf"}
	for _, k := range expectedKeys {
		if _, ok := received.Files[k]; !ok {
			t.Errorf("agent did not receive expected file key %q; got keys: %v", k, keys(received.Files))
		}
	}
}

func TestGenerateAndTest_AgentMode_RouteConfContent(t *testing.T) {
	var received agentApplyRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "ok", "output": "ok"})
	}))
	defer srv.Close()

	gen := newAgentGenerator(t, srv.URL)
	r := validRoute(5)
	gen.GenerateAndTest([]*models.Route{r}, defaultSettings())

	conf, ok := received.Files["routes/5.conf"]
	if !ok {
		t.Fatal("routes/5.conf not sent to agent")
	}
	if !strings.Contains(conf, "server_name app1.example.com") {
		t.Errorf("expected server_name in route conf, got: %s", conf)
	}
	if !strings.Contains(conf, "proxy_pass http://backend1:8080") {
		t.Errorf("expected proxy_pass in route conf, got: %s", conf)
	}
}

func TestGenerateAndTest_AgentMode_AgentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "nginx config test failed",
			"output": "nginx: configuration file error",
		})
	}))
	defer srv.Close()

	gen := newAgentGenerator(t, srv.URL)
	_, err := gen.GenerateAndTest([]*models.Route{validRoute(1)}, defaultSettings())
	if err == nil {
		t.Fatal("expected error when agent returns 400")
	}
}

func TestGenerateAndTest_AgentMode_AgentUnreachable(t *testing.T) {
	gen := newAgentGenerator(t, "http://127.0.0.1:19999") // nothing listening there
	_, err := gen.GenerateAndTest([]*models.Route{validRoute(1)}, defaultSettings())
	if err == nil {
		t.Fatal("expected error when agent is unreachable")
	}
}

func TestReload_AgentMode_IsNoOp(t *testing.T) {
	gen := newAgentGenerator(t, "http://127.0.0.1:19999") // never called
	out, err := gen.Reload()
	if err != nil {
		t.Fatalf("Reload should be a no-op in agent mode, got error: %v", err)
	}
	if out != "" {
		t.Errorf("Reload no-op should return empty string, got: %q", out)
	}
}

func TestGenerateAndTest_AgentMode_SendsAuthToken(t *testing.T) {
	var receivedToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "ok", "output": "ok"})
	}))
	defer srv.Close()

	gen := newAgentGenerator(t, srv.URL)
	gen.AgentToken = "my-secret-token"
	gen.GenerateAndTest([]*models.Route{validRoute(1)}, defaultSettings())

	if receivedToken != "Bearer my-secret-token" {
		t.Errorf("expected Authorization header 'Bearer my-secret-token', got %q", receivedToken)
	}
}

// keys returns the keys of a map[string]string for error messages.
func keys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
