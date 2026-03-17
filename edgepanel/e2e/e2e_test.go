// Package e2e contains end-to-end tests that start a real HTTP server (backed
// by an in-memory SQLite database) and exercise the full API flow using the
// standard net/http client — no mocks, no httptest.Handler tricks.
//
// The tests cover the most important user journeys:
//  1. Login → get JWT token
//  2. CRUD routes
//  3. Maintenance toggle
//  4. IP filter update
//  5. Global settings update
//  6. Audit log visibility
//  7. User management (create / assign)
//  8. RBAC enforcement
package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mehmettopcu/edgepanel/internal/api"
	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
)

// ---------------------------------------------------------------------------
// Server fixture
// ---------------------------------------------------------------------------

// serverFixture holds a real HTTP test server wired to a temporary SQLite DB.
type serverFixture struct {
	Server   *httptest.Server
	DB       *db.DB
	BaseURL  string
	AdminJWT string
}

func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()
	t.Setenv("JWT_SECRET", "e2e-test-secret-key")

	// Create isolated DB
	dir := t.TempDir()
	database, err := db.New(filepath.Join(dir, "e2e.db"))
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	if err := database.SeedInitialData(); err != nil {
		t.Fatalf("SeedInitialData: %v", err)
	}

	// Nginx generator (no real nginx binary available in CI)
	nginxDir, _ := os.MkdirTemp("", "e2e-nginx-*")
	gen := nginx.New(nginxDir, "/nonexistent/nginx")

	// Build chi router identical to main.go (minus the embedded templates)
	tmpl := template.Must(template.New("dummy").Parse("{{.}}"))
	_ = tmpl

	authHandler := &api.AuthHandler{DB: database}
	routesHandler := &api.RoutesHandler{DB: database}
	usersHandler := &api.UsersHandler{DB: database}
	applyHandler := &api.ApplyHandler{DB: database, Generator: gen}
	auditHandler := &api.AuditHandler{DB: database}
	settingsHandler := &api.SettingsHandler{DB: database}

	r := chi.NewRouter()

	r.Post("/api/auth/login", authHandler.Login)
	r.Post("/api/auth/logout", authHandler.Logout)

	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Get("/api/me", authHandler.Me)
		r.Get("/api/routes", routesHandler.List)
		r.Get("/api/routes/{id}", routesHandler.Get)
		r.Put("/api/routes/{id}", routesHandler.Update)
		r.Post("/api/routes/{id}/maintenance", routesHandler.ToggleMaintenance)
		r.Post("/api/routes/{id}/ip-filter", routesHandler.SetIPFilter)
		r.Post("/api/apply", applyHandler.Apply)
		r.Get("/api/audit", auditHandler.List)
		r.Get("/api/schema", settingsHandler.GetSchema)
		r.Get("/api/settings", settingsHandler.GetSettings)
		r.With(auth.AdminOnly).Put("/api/settings", settingsHandler.UpdateSettings)

		r.Group(func(r chi.Router) {
			r.Use(auth.AdminOnly)
			r.Post("/api/routes", routesHandler.Create)
			r.Get("/api/users", usersHandler.List)
			r.Post("/api/users", usersHandler.Create)
			r.Put("/api/users/{id}", usersHandler.Update)
			r.Post("/api/users/{id}/assignments", usersHandler.Assign)
		})
	})

	srv := httptest.NewServer(r)
	t.Cleanup(func() {
		srv.Close()
		os.RemoveAll(nginxDir)
	})

	// Log in as admin and obtain JWT
	jwtToken := loginAs(t, srv.URL, "admin", "admin")

	return &serverFixture{
		Server:   srv,
		DB:       database,
		BaseURL:  srv.URL,
		AdminJWT: jwtToken,
	}
}

// ---------------------------------------------------------------------------
// HTTP client helpers
// ---------------------------------------------------------------------------

func loginAs(t *testing.T, baseURL, username, password string) string {
	t.Helper()
	body := map[string]string{"username": username, "password": password}
	resp := doRequest(t, baseURL, http.MethodPost, "/api/auth/login", "", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login failed (%d): %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatal("login did not return a token")
	}
	return token
}

func doRequest(t *testing.T, baseURL, method, path, token string, body interface{}) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, baseURL+path, r)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http.Do: %v", err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, dst interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E test: Authentication flow
// ---------------------------------------------------------------------------

func TestE2E_Login_Success(t *testing.T) {
	f := newServerFixture(t)
	// adminJWT was obtained during fixture setup; just verify it's non-empty
	if f.AdminJWT == "" {
		t.Fatal("expected non-empty admin JWT")
	}
}

func TestE2E_Login_BadCredentials(t *testing.T) {
	f := newServerFixture(t)
	resp := doRequest(t, f.BaseURL, http.MethodPost, "/api/auth/login", "", map[string]string{
		"username": "admin", "password": "wrongpass",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestE2E_Me_ReturnsAdminInfo(t *testing.T) {
	f := newServerFixture(t)
	resp := doRequest(t, f.BaseURL, http.MethodGet, "/api/me", f.AdminJWT, nil)
	var out map[string]interface{}
	decodeJSON(t, resp, &out)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if out["username"] != "admin" {
		t.Errorf("expected username 'admin', got %v", out["username"])
	}
	if out["is_admin"] != true {
		t.Errorf("expected is_admin true, got %v", out["is_admin"])
	}
}

func TestE2E_Logout(t *testing.T) {
	f := newServerFixture(t)
	resp := doRequest(t, f.BaseURL, http.MethodPost, "/api/auth/logout", f.AdminJWT, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// E2E test: Route lifecycle
// ---------------------------------------------------------------------------

func TestE2E_FullRouteCRUD(t *testing.T) {
	f := newServerFixture(t)

	// 1. Create a new route
	createBody := map[string]interface{}{
		"name":               "e2eapp",
		"subdomain":          "e2eapp.localtest.me",
		"upstream":           "http://backend-e2e:8080",
		"waf_paranoia_level": 1,
	}
	createResp := doRequest(t, f.BaseURL, http.MethodPost, "/api/routes", f.AdminJWT, createBody)
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		createResp.Body.Close()
		t.Fatalf("expected 201, got %d: %s", createResp.StatusCode, b)
	}
	var created map[string]interface{}
	decodeJSON(t, createResp, &created)
	routeID := int64(created["id"].(float64))
	if routeID == 0 {
		t.Fatal("expected non-zero route ID")
	}

	// 2. Fetch the route
	getResp := doRequest(t, f.BaseURL, http.MethodGet, fmt.Sprintf("/api/routes/%d", routeID), f.AdminJWT, nil)
	if getResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", getResp.StatusCode, b)
	}
	var fetched map[string]interface{}
	decodeJSON(t, getResp, &fetched)
	if fetched["name"] != "e2eapp" {
		t.Errorf("expected name 'e2eapp', got %v", fetched["name"])
	}

	// 3. Update the route
	updateBody := map[string]interface{}{
		"name":               "e2eapp-updated",
		"subdomain":          "e2eapp.localtest.me",
		"upstream":           "http://backend-e2e:9090",
		"waf_paranoia_level": 2,
	}
	updateResp := doRequest(t, f.BaseURL, http.MethodPut, fmt.Sprintf("/api/routes/%d", routeID), f.AdminJWT, updateBody)
	if updateResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(updateResp.Body)
		updateResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", updateResp.StatusCode, b)
	}
	var updated map[string]interface{}
	decodeJSON(t, updateResp, &updated)
	if updated["name"] != "e2eapp-updated" {
		t.Errorf("expected updated name, got %v", updated["name"])
	}

	// 4. List routes — should include the new one
	listResp := doRequest(t, f.BaseURL, http.MethodGet, "/api/routes", f.AdminJWT, nil)
	var routes []map[string]interface{}
	decodeJSON(t, listResp, &routes)
	found := false
	for _, r := range routes {
		if int64(r["id"].(float64)) == routeID {
			found = true
		}
	}
	if !found {
		t.Error("newly created route should appear in the list")
	}
}

func TestE2E_CreateRoute_ValidationError(t *testing.T) {
	f := newServerFixture(t)

	body := map[string]interface{}{
		"name":      "",         // required, but empty
		"subdomain": "x.e2e.me",
		"upstream":  "not-url", // invalid URL
	}
	resp := doRequest(t, f.BaseURL, http.MethodPost, "/api/routes", f.AdminJWT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// E2E test: Maintenance toggle
// ---------------------------------------------------------------------------

func TestE2E_ToggleMaintenance(t *testing.T) {
	f := newServerFixture(t)

	// Enable maintenance on route 1 (seeded)
	enableBody := map[string]interface{}{"enabled": true, "mode": "global"}
	resp := doRequest(t, f.BaseURL, http.MethodPost, "/api/routes/1/maintenance", f.AdminJWT, enableBody)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
	}
	var route map[string]interface{}
	decodeJSON(t, resp, &route)
	if route["maintenance_enabled"] != true {
		t.Error("expected maintenance_enabled=true")
	}

	// Disable maintenance
	disableBody := map[string]interface{}{"enabled": false, "mode": "global"}
	resp2 := doRequest(t, f.BaseURL, http.MethodPost, "/api/routes/1/maintenance", f.AdminJWT, disableBody)
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp2.StatusCode, b)
	}
	var route2 map[string]interface{}
	decodeJSON(t, resp2, &route2)
	if route2["maintenance_enabled"] != false {
		t.Error("expected maintenance_enabled=false after disabling")
	}
}

// ---------------------------------------------------------------------------
// E2E test: IP filter
// ---------------------------------------------------------------------------

func TestE2E_SetIPFilter(t *testing.T) {
	f := newServerFixture(t)

	body := map[string]interface{}{
		"enabled":        true,
		"default_policy": "deny",
		"allowlist":      "10.0.0.0/8\n192.168.0.1",
		"denylist":       "1.2.3.4",
	}
	resp := doRequest(t, f.BaseURL, http.MethodPost, "/api/routes/1/ip-filter", f.AdminJWT, body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
	}
	var route map[string]interface{}
	decodeJSON(t, resp, &route)
	if route["ip_filter_enabled"] != true {
		t.Error("expected ip_filter_enabled=true")
	}
	if route["ip_default_policy"] != "deny" {
		t.Errorf("expected ip_default_policy=deny, got %v", route["ip_default_policy"])
	}
}

// ---------------------------------------------------------------------------
// E2E test: Global settings
// ---------------------------------------------------------------------------

func TestE2E_GetAndUpdateSettings(t *testing.T) {
	f := newServerFixture(t)

	// Get
	getResp := doRequest(t, f.BaseURL, http.MethodGet, "/api/settings", f.AdminJWT, nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	var gs map[string]interface{}
	decodeJSON(t, getResp, &gs)

	// Update paranoia level
	putBody := map[string]interface{}{"waf_enabled": true, "waf_paranoia_level": 4}
	putResp := doRequest(t, f.BaseURL, http.MethodPut, "/api/settings", f.AdminJWT, putBody)
	if putResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(putResp.Body)
		putResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", putResp.StatusCode, b)
	}
	var updated map[string]interface{}
	decodeJSON(t, putResp, &updated)
	if int(updated["waf_paranoia_level"].(float64)) != 4 {
		t.Errorf("expected waf_paranoia_level=4, got %v", updated["waf_paranoia_level"])
	}
}

// ---------------------------------------------------------------------------
// E2E test: Audit log
// ---------------------------------------------------------------------------

func TestE2E_AuditLogRecordsActions(t *testing.T) {
	f := newServerFixture(t)

	// Perform a create-route action so we have at least one audit log entry
	doRequest(t, f.BaseURL, http.MethodPost, "/api/routes", f.AdminJWT, map[string]interface{}{
		"name": "audit-test", "subdomain": "audit.localtest.me", "upstream": "http://backend:80",
		"waf_paranoia_level": 1,
	})

	resp := doRequest(t, f.BaseURL, http.MethodGet, "/api/audit", f.AdminJWT, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var logs []map[string]interface{}
	decodeJSON(t, resp, &logs)
	if len(logs) == 0 {
		t.Error("expected at least one audit log entry")
	}
}

// ---------------------------------------------------------------------------
// E2E test: User management
// ---------------------------------------------------------------------------

func TestE2E_CreateUserAndAssignRole(t *testing.T) {
	f := newServerFixture(t)

	// Create user
	createBody := map[string]string{"username": "e2e-operator", "password": "Str0ngP@ss!"}
	createResp := doRequest(t, f.BaseURL, http.MethodPost, "/api/users", f.AdminJWT, createBody)
	if createResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(createResp.Body)
		createResp.Body.Close()
		t.Fatalf("expected 201, got %d: %s", createResp.StatusCode, b)
	}
	var user map[string]interface{}
	decodeJSON(t, createResp, &user)
	userID := int64(user["id"].(float64))

	// Assign operator role on route 1
	assignBody := map[string]interface{}{"route_id": 1, "role": "operator"}
	assignResp := doRequest(t, f.BaseURL, http.MethodPost, fmt.Sprintf("/api/users/%d/assignments", userID), f.AdminJWT, assignBody)
	if assignResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(assignResp.Body)
		assignResp.Body.Close()
		t.Fatalf("expected 200, got %d: %s", assignResp.StatusCode, b)
	}
	assignResp.Body.Close()

	// Log in as the new operator
	operatorJWT := loginAs(t, f.BaseURL, "e2e-operator", "Str0ngP@ss!")

	// Operator should be able to read assigned route
	routeResp := doRequest(t, f.BaseURL, http.MethodGet, "/api/routes/1", operatorJWT, nil)
	if routeResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(routeResp.Body)
		routeResp.Body.Close()
		t.Fatalf("operator should access assigned route, got %d: %s", routeResp.StatusCode, b)
	}
	routeResp.Body.Close()

	// Operator should NOT be able to access route 2 (not assigned)
	route2Resp := doRequest(t, f.BaseURL, http.MethodGet, "/api/routes/2", operatorJWT, nil)
	if route2Resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(route2Resp.Body)
		route2Resp.Body.Close()
		t.Errorf("operator should get 403 for unassigned route 2, got %d: %s", route2Resp.StatusCode, b)
	}
	route2Resp.Body.Close()
}

// ---------------------------------------------------------------------------
// E2E test: RBAC — viewers cannot write
// ---------------------------------------------------------------------------

func TestE2E_ViewerCannotCreateRoute(t *testing.T) {
	f := newServerFixture(t)

	// Create a viewer user
	createBody := map[string]string{"username": "e2e-viewer", "password": "ViewerPass1!"}
	createResp := doRequest(t, f.BaseURL, http.MethodPost, "/api/users", f.AdminJWT, createBody)
	var user map[string]interface{}
	decodeJSON(t, createResp, &user)

	viewerJWT := loginAs(t, f.BaseURL, "e2e-viewer", "ViewerPass1!")

	// Try to create a route — should be forbidden
	body := map[string]interface{}{
		"name": "viewer-route", "subdomain": "vr.localtest.me", "upstream": "http://b:80",
		"waf_paranoia_level": 1,
	}
	resp := doRequest(t, f.BaseURL, http.MethodPost, "/api/routes", viewerJWT, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// E2E test: Config schema endpoint
// ---------------------------------------------------------------------------

func TestE2E_Schema(t *testing.T) {
	f := newServerFixture(t)

	resp := doRequest(t, f.BaseURL, http.MethodGet, "/api/schema", f.AdminJWT, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var schema []map[string]interface{}
	decodeJSON(t, resp, &schema)
	if len(schema) == 0 {
		t.Error("expected non-empty schema")
	}
	found := false
	for _, s := range schema {
		if s["param_name"] == "upstream" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'upstream' schema entry")
	}
}

// ---------------------------------------------------------------------------
// E2E test: Unauthenticated access is denied
// ---------------------------------------------------------------------------

func TestE2E_UnauthenticatedRequestsDenied(t *testing.T) {
	f := newServerFixture(t)

	protectedPaths := []string{
		"/api/me",
		"/api/routes",
		"/api/settings",
		"/api/audit",
		"/api/schema",
	}
	for _, path := range protectedPaths {
		resp := doRequest(t, f.BaseURL, http.MethodGet, path, "" /* no token */, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for %s, got %d", path, resp.StatusCode)
		}
	}
}

// ---------------------------------------------------------------------------
// E2E test: Server is actually listening on a real TCP port
// ---------------------------------------------------------------------------

func TestE2E_ServerListensOnTCPPort(t *testing.T) {
	f := newServerFixture(t)

	addr := f.Server.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("could not connect to server at %s: %v", addr, err)
	}
	conn.Close()
}
