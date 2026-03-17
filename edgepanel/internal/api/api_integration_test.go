// Package api_test contains integration tests for the HTTP API handlers.
// Each test spins up a real chi router backed by an in-memory SQLite DB so
// no mocks are needed and the full middleware/auth chain is exercised.
package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mehmettopcu/edgepanel/internal/api"
	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/models"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func setupDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	database, err := db.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	if err := database.SeedInitialData(); err != nil {
		t.Fatalf("SeedInitialData: %v", err)
	}
	return database
}

// adminToken returns a JWT for the seeded admin user.
func adminToken(t *testing.T) string {
	t.Helper()
	t.Setenv("JWT_SECRET", "integration-test-secret")
	token, err := auth.GenerateToken(1, "admin", true)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return token
}

// nonAdminToken returns a JWT for a non-admin user.
func nonAdminToken(t *testing.T, userID int64, username string) string {
	t.Helper()
	t.Setenv("JWT_SECRET", "integration-test-secret")
	token, err := auth.GenerateToken(userID, username, false)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return token
}

func authReq(method, path, token string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func setupRouter(database *db.DB) http.Handler {
	dir, _ := os.MkdirTemp("", "nginx-gen-*")
	gen := nginx.New(dir, "/nonexistent/nginx")

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
	return r
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func TestLogin_Success(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]string{"username": "admin", "password": "admin"}
	req := authReq(http.MethodPost, "/api/auth/login", "", body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("expected token in response")
	}
	if resp["username"] != "admin" {
		t.Errorf("expected username 'admin', got %v", resp["username"])
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]string{"username": "admin", "password": "wrongpassword"}
	req := authReq(http.MethodPost, "/api/auth/login", "", body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]string{"username": "ghost", "password": "pass"}
	req := authReq(http.MethodPost, "/api/auth/login", "", body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestLogout(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodPost, "/api/auth/logout", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMe_Authenticated(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/me", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["username"] != "admin" {
		t.Errorf("expected username 'admin', got %v", resp["username"])
	}
}

func TestMe_Unauthenticated(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

func TestListRoutes_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/routes", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var routes []models.Route
	json.NewDecoder(rr.Body).Decode(&routes)
	// Seed creates 2 default routes
	if len(routes) < 2 {
		t.Errorf("expected at least 2 seeded routes, got %d", len(routes))
	}
}

func TestCreateRoute_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]interface{}{
		"name":               "newapp",
		"subdomain":          "newapp.localtest.me",
		"upstream":           "http://backend3:8080",
		"waf_paranoia_level": 1,
	}
	req := authReq(http.MethodPost, "/api/routes", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var route models.Route
	json.NewDecoder(rr.Body).Decode(&route)
	if route.ID == 0 {
		t.Error("expected non-zero route ID in response")
	}
	if route.Name != "newapp" {
		t.Errorf("expected name 'newapp', got %q", route.Name)
	}
}

func TestCreateRoute_NonAdmin_Forbidden(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	// Create a second user (non-admin)
	hash, _ := auth.HashPassword("pass")
	u, _ := database.CreateUser("viewer1", hash)
	token := nonAdminToken(t, u.ID, u.Username)

	body := map[string]interface{}{
		"name":      "myapp",
		"subdomain": "myapp.localtest.me",
		"upstream":  "http://backend3:8080",
	}
	req := authReq(http.MethodPost, "/api/routes", token, body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestCreateRoute_ValidationError(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	// Missing name, invalid upstream
	body := map[string]interface{}{
		"name":      "",
		"subdomain": "x.localtest.me",
		"upstream":  "not-a-url",
	}
	req := authReq(http.MethodPost, "/api/routes", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", rr.Code)
	}
}

func TestGetRoute_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	// Route ID 1 is created by seed
	req := authReq(http.MethodGet, "/api/routes/1", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGetRoute_NotFound(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/routes/9999", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestUpdateRoute_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]interface{}{
		"name":               "app1-updated",
		"subdomain":          "app1.localtest.me",
		"upstream":           "http://backend1:9090",
		"waf_paranoia_level": 2,
	}
	req := authReq(http.MethodPut, "/api/routes/1", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var route models.Route
	json.NewDecoder(rr.Body).Decode(&route)
	if route.Name != "app1-updated" {
		t.Errorf("expected updated name, got %q", route.Name)
	}
}

func TestToggleMaintenance_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]interface{}{
		"enabled": true,
		"mode":    "global",
	}
	req := authReq(http.MethodPost, "/api/routes/1/maintenance", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var route models.Route
	json.NewDecoder(rr.Body).Decode(&route)
	if !route.MaintenanceEnabled {
		t.Error("expected maintenance to be enabled")
	}
}

func TestSetIPFilter_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]interface{}{
		"enabled":        true,
		"default_policy": "deny",
		"allowlist":      "192.168.1.0/24",
		"denylist":       "",
	}
	req := authReq(http.MethodPost, "/api/routes/1/ip-filter", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var route models.Route
	json.NewDecoder(rr.Body).Decode(&route)
	if !route.IPFilterEnabled {
		t.Error("expected IP filter to be enabled")
	}
	if route.IPDefaultPolicy != "deny" {
		t.Errorf("expected deny policy, got %q", route.IPDefaultPolicy)
	}
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func TestListUsers_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/users", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var users []models.User
	json.NewDecoder(rr.Body).Decode(&users)
	if len(users) < 1 {
		t.Error("expected at least 1 user (admin)")
	}
}

func TestCreateUser_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]string{"username": "operator1", "password": "Op3ratorPass!"}
	req := authReq(http.MethodPost, "/api/users", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var user models.User
	json.NewDecoder(rr.Body).Decode(&user)
	if user.Username != "operator1" {
		t.Errorf("expected username 'operator1', got %q", user.Username)
	}
}

func TestCreateUser_MissingFields(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]string{"username": "incomplete"}
	req := authReq(http.MethodPost, "/api/users", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAssignRole(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	// Create a user to assign
	hash, _ := auth.HashPassword("pass")
	u, _ := database.CreateUser("operatorX", hash)

	body := map[string]interface{}{"route_id": 1, "role": "operator"}
	req := authReq(http.MethodPost, "/api/users/"+itoa(u.ID)+"/assignments", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAssignRole_InvalidRole(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	hash, _ := auth.HashPassword("pass")
	u, _ := database.CreateUser("operatorY", hash)

	body := map[string]interface{}{"route_id": 1, "role": "superuser"}
	req := authReq(http.MethodPost, "/api/users/"+itoa(u.ID)+"/assignments", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func TestGetSettings(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/settings", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var gs models.GlobalSettings
	json.NewDecoder(rr.Body).Decode(&gs)
	if gs.WAFParanoiaLevel < 1 || gs.WAFParanoiaLevel > 4 {
		t.Errorf("expected paranoia level 1-4, got %d", gs.WAFParanoiaLevel)
	}
}

func TestUpdateSettings_Admin(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]interface{}{"waf_enabled": true, "waf_paranoia_level": 3}
	req := authReq(http.MethodPut, "/api/settings", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var gs models.GlobalSettings
	json.NewDecoder(rr.Body).Decode(&gs)
	if gs.WAFParanoiaLevel != 3 {
		t.Errorf("expected paranoia level 3, got %d", gs.WAFParanoiaLevel)
	}
}

func TestUpdateSettings_InvalidLevel(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	body := map[string]interface{}{"waf_enabled": true, "waf_paranoia_level": 10}
	req := authReq(http.MethodPut, "/api/settings", adminToken(t), body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", rr.Code)
	}
}

func TestUpdateSettings_NonAdmin_Forbidden(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	hash, _ := auth.HashPassword("pass")
	u, _ := database.CreateUser("viewer2", hash)
	token := nonAdminToken(t, u.ID, u.Username)

	body := map[string]interface{}{"waf_enabled": false, "waf_paranoia_level": 1}
	req := authReq(http.MethodPut, "/api/settings", token, body)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func TestGetSchema(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/schema", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var schema []models.NginxConfigSchema
	json.NewDecoder(rr.Body).Decode(&schema)
	if len(schema) == 0 {
		t.Error("expected schema entries")
	}
}

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------

func TestListAuditLogs(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodGet, "/api/audit", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Apply — expect nginx error since binary doesn't exist in CI
// ---------------------------------------------------------------------------

func TestApply_NginxBinaryMissing(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	req := authReq(http.MethodPost, "/api/apply", adminToken(t), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// We expect either 400 (nginx -t failed) or 500 (reload failed) because
	// the nginx binary doesn't exist. Either way, it must not be 200.
	if rr.Code == http.StatusOK {
		t.Error("apply should fail when nginx binary is missing")
	}
}

// ---------------------------------------------------------------------------
// RBAC: non-admin user can only access assigned routes
// ---------------------------------------------------------------------------

func TestGetRoute_NonAdmin_Forbidden_NotAssigned(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	hash, _ := auth.HashPassword("pass")
	u, _ := database.CreateUser("viewer3", hash)
	token := nonAdminToken(t, u.ID, u.Username)

	// Route 1 exists but user is not assigned
	req := authReq(http.MethodGet, "/api/routes/1", token, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unassigned route, got %d", rr.Code)
	}
}

func TestGetRoute_NonAdmin_Allowed_WhenAssigned(t *testing.T) {
	t.Setenv("JWT_SECRET", "integration-test-secret")
	database := setupDB(t)
	router := setupRouter(database)

	hash, _ := auth.HashPassword("pass")
	u, _ := database.CreateUser("viewer4", hash)
	database.UpsertAssignment(u.ID, 1, "viewer")
	token := nonAdminToken(t, u.ID, u.Username)

	req := authReq(http.MethodGet, "/api/routes/1", token, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for assigned route, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// small helper — int64 to string without fmt
// ---------------------------------------------------------------------------

func itoa(id int64) string {
	b := make([]byte, 0, 20)
	if id == 0 {
		return "0"
	}
	for id > 0 {
		b = append([]byte{byte('0' + id%10)}, b...)
		id /= 10
	}
	return string(b)
}
