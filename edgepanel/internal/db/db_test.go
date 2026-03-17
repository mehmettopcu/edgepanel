package db_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/models"
)

// newTestDB creates a temporary SQLite database for testing.
func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	database, err := db.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.New error: %v", err)
	}
	return database
}

// newSeededDB creates a DB that has been seeded with initial data.
func newSeededDB(t *testing.T) *db.DB {
	t.Helper()
	d := newTestDB(t)
	if err := d.SeedInitialData(); err != nil {
		t.Fatalf("SeedInitialData error: %v", err)
	}
	return d
}

// ---------------------------------------------------------------------------
// Migration / seed
// ---------------------------------------------------------------------------

func TestNew_MigratesSuccessfully(t *testing.T) {
	d := newTestDB(t)
	if d == nil {
		t.Fatal("expected non-nil DB")
	}
}

func TestSeedInitialData_CreatesAdminUser(t *testing.T) {
	d := newSeededDB(t)

	user, err := d.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername error: %v", err)
	}
	if user == nil {
		t.Fatal("expected admin user to exist after seed")
	}
	if !user.IsActive {
		t.Error("admin user should be active")
	}
	if !auth.CheckPassword(user.PasswordHash, "admin") {
		t.Error("admin password should be 'admin' after seed")
	}
}

func TestSeedInitialData_Idempotent(t *testing.T) {
	d := newSeededDB(t)
	// Calling SeedInitialData a second time should not fail or create duplicates.
	if err := d.SeedInitialData(); err != nil {
		t.Fatalf("second SeedInitialData call error: %v", err)
	}
	users, err := d.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers error: %v", err)
	}
	adminCount := 0
	for _, u := range users {
		if u.Username == "admin" {
			adminCount++
		}
	}
	if adminCount != 1 {
		t.Errorf("expected exactly 1 admin user, got %d", adminCount)
	}
}

// ---------------------------------------------------------------------------
// User CRUD
// ---------------------------------------------------------------------------

func TestCreateAndGetUser(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("password123")
	user, err := d.CreateUser("testuser", hash)
	if err != nil {
		t.Fatalf("CreateUser error: %v", err)
	}
	if user.ID == 0 {
		t.Error("expected non-zero user ID")
	}
	if user.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", user.Username)
	}
	if !user.IsActive {
		t.Error("new user should be active")
	}

	// Fetch by ID
	fetched, err := d.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("GetUserByID error: %v", err)
	}
	if fetched == nil || fetched.Username != "testuser" {
		t.Error("GetUserByID should return the created user")
	}
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	d := newTestDB(t)
	user, err := d.GetUserByUsername("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil for unknown user")
	}
}

func TestGetUserByID_NotFound(t *testing.T) {
	d := newTestDB(t)
	user, err := d.GetUserByID(9999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil for unknown user ID")
	}
}

func TestUpdateUser_ChangePassword(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("oldpassword")
	user, _ := d.CreateUser("updateme", hash)

	newHash, _ := auth.HashPassword("newpassword")
	if err := d.UpdateUser(user.ID, user.Username, true, newHash); err != nil {
		t.Fatalf("UpdateUser error: %v", err)
	}

	updated, _ := d.GetUserByID(user.ID)
	if !auth.CheckPassword(updated.PasswordHash, "newpassword") {
		t.Error("password should have been updated")
	}
}

func TestUpdateUser_DisableUser(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("pass")
	user, _ := d.CreateUser("disableme", hash)

	if err := d.UpdateUser(user.ID, user.Username, false, ""); err != nil {
		t.Fatalf("UpdateUser error: %v", err)
	}
	updated, _ := d.GetUserByID(user.ID)
	if updated.IsActive {
		t.Error("user should be inactive after disabling")
	}
}

func TestListUsers(t *testing.T) {
	d := newTestDB(t)

	h1, _ := auth.HashPassword("p1")
	h2, _ := auth.HashPassword("p2")
	d.CreateUser("user1", h1)
	d.CreateUser("user2", h2)

	users, err := d.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers error: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

// ---------------------------------------------------------------------------
// Route CRUD
// ---------------------------------------------------------------------------

func newValidRoute() *models.Route {
	return &models.Route{
		Name:             "myapp",
		Subdomain:        "myapp.example.com",
		Upstream:         "http://backend:8080",
		MaintenanceMode:  "global",
		IPDefaultPolicy:  "allow",
		WAFParanoiaLevel: 1,
	}
}

func TestCreateAndGetRoute(t *testing.T) {
	d := newTestDB(t)

	r, err := d.CreateRoute(newValidRoute())
	if err != nil {
		t.Fatalf("CreateRoute error: %v", err)
	}
	if r.ID == 0 {
		t.Error("expected non-zero route ID")
	}
	if r.Name != "myapp" {
		t.Errorf("expected name 'myapp', got %q", r.Name)
	}

	fetched, err := d.GetRouteByID(r.ID)
	if err != nil {
		t.Fatalf("GetRouteByID error: %v", err)
	}
	if fetched == nil || fetched.Name != "myapp" {
		t.Error("GetRouteByID should return the created route")
	}
}

func TestGetRouteByID_NotFound(t *testing.T) {
	d := newTestDB(t)
	r, err := d.GetRouteByID(9999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Error("expected nil for unknown route ID")
	}
}

func TestUpdateRoute(t *testing.T) {
	d := newTestDB(t)
	r, _ := d.CreateRoute(newValidRoute())

	r.Name = "renamed"
	r.Upstream = "http://newbackend:9090"
	if err := d.UpdateRoute(r); err != nil {
		t.Fatalf("UpdateRoute error: %v", err)
	}

	updated, _ := d.GetRouteByID(r.ID)
	if updated.Name != "renamed" {
		t.Errorf("expected name 'renamed', got %q", updated.Name)
	}
	if updated.Upstream != "http://newbackend:9090" {
		t.Errorf("expected new upstream, got %q", updated.Upstream)
	}
}

func TestListRoutes(t *testing.T) {
	d := newTestDB(t)

	r1 := newValidRoute()
	r2 := &models.Route{Name: "app2", Subdomain: "app2.example.com", Upstream: "http://b2:80", MaintenanceMode: "global", IPDefaultPolicy: "allow", WAFParanoiaLevel: 1}
	d.CreateRoute(r1)
	d.CreateRoute(r2)

	routes, err := d.ListRoutes()
	if err != nil {
		t.Fatalf("ListRoutes error: %v", err)
	}
	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}
}

func TestListRoutesByUserID(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("pass")
	user, _ := d.CreateUser("operator1", hash)
	r1, _ := d.CreateRoute(newValidRoute())
	r2 := &models.Route{Name: "app2", Subdomain: "app2.example.com", Upstream: "http://b2:80", MaintenanceMode: "global", IPDefaultPolicy: "allow", WAFParanoiaLevel: 1}
	r2, _ = d.CreateRoute(r2)

	// Assign user to r1 only
	d.UpsertAssignment(user.ID, r1.ID, "operator")

	routes, err := d.ListRoutesByUserID(user.ID)
	if err != nil {
		t.Fatalf("ListRoutesByUserID error: %v", err)
	}
	if len(routes) != 1 {
		t.Errorf("expected 1 route for operator, got %d", len(routes))
	}
	if routes[0].ID != r1.ID {
		t.Errorf("expected route ID %d, got %d", r1.ID, routes[0].ID)
	}
	_ = r2
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

func TestUpsertAndGetAssignment(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("pass")
	user, _ := d.CreateUser("op", hash)
	route, _ := d.CreateRoute(newValidRoute())

	if err := d.UpsertAssignment(user.ID, route.ID, "operator"); err != nil {
		t.Fatalf("UpsertAssignment error: %v", err)
	}

	a, err := d.GetAssignment(user.ID, route.ID)
	if err != nil {
		t.Fatalf("GetAssignment error: %v", err)
	}
	if a == nil {
		t.Fatal("expected assignment, got nil")
	}
	if a.Role != "operator" {
		t.Errorf("expected role 'operator', got %q", a.Role)
	}

	// Upsert again with different role
	d.UpsertAssignment(user.ID, route.ID, "viewer")
	a2, _ := d.GetAssignment(user.ID, route.ID)
	if a2.Role != "viewer" {
		t.Errorf("expected updated role 'viewer', got %q", a2.Role)
	}
}

func TestGetAssignment_NotFound(t *testing.T) {
	d := newTestDB(t)
	a, err := d.GetAssignment(999, 999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a != nil {
		t.Error("expected nil for unknown assignment")
	}
}

// ---------------------------------------------------------------------------
// IsAdmin
// ---------------------------------------------------------------------------

func TestIsAdmin_FirstUser(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("pass")
	user, _ := d.CreateUser("firstuser", hash)

	if !d.IsAdmin(user.ID) {
		t.Error("first created user (id=1) should be admin")
	}
}

func TestIsAdmin_NonAdminNoAssignment(t *testing.T) {
	d := newTestDB(t)

	hash, _ := auth.HashPassword("p1")
	h2, _ := auth.HashPassword("p2")
	d.CreateUser("first", hash)
	user2, _ := d.CreateUser("second", h2)

	if d.IsAdmin(user2.ID) {
		t.Error("second user without admin assignment should not be admin")
	}
}

func TestIsAdmin_WithAdminAssignment(t *testing.T) {
	d := newTestDB(t)

	h1, _ := auth.HashPassword("p1")
	h2, _ := auth.HashPassword("p2")
	d.CreateUser("first", h1)
	user2, _ := d.CreateUser("promoted", h2)
	route, _ := d.CreateRoute(newValidRoute())

	d.UpsertAssignment(user2.ID, route.ID, "admin")

	if !d.IsAdmin(user2.ID) {
		t.Error("user with admin assignment should be recognized as admin")
	}
}

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------

func TestCreateAndListAuditLogs(t *testing.T) {
	d := newTestDB(t)

	uid := int64(1)
	rid := int64(10)
	if err := d.CreateAuditLog(&uid, "admin", "test_action", "route", &rid, "details"); err != nil {
		t.Fatalf("CreateAuditLog error: %v", err)
	}

	logs, err := d.ListAuditLogs(10)
	if err != nil {
		t.Fatalf("ListAuditLogs error: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("expected 1 audit log, got %d", len(logs))
	}
	if logs[0].Action != "test_action" {
		t.Errorf("expected action 'test_action', got %q", logs[0].Action)
	}
}

func TestListAuditLogs_DefaultLimit(t *testing.T) {
	d := newTestDB(t)

	uid := int64(1)
	for i := 0; i < 5; i++ {
		d.CreateAuditLog(&uid, "admin", "action", "route", nil, "")
	}

	// limit=0 should use default (100)
	logs, err := d.ListAuditLogs(0)
	if err != nil {
		t.Fatalf("ListAuditLogs error: %v", err)
	}
	if len(logs) != 5 {
		t.Errorf("expected 5 logs, got %d", len(logs))
	}
}

// ---------------------------------------------------------------------------
// Global settings
// ---------------------------------------------------------------------------

func TestGetAndUpdateGlobalSettings(t *testing.T) {
	d := newSeededDB(t)

	gs, err := d.GetGlobalSettings()
	if err != nil {
		t.Fatalf("GetGlobalSettings error: %v", err)
	}
	if gs == nil {
		t.Fatal("expected non-nil global settings")
	}

	gs.WAFEnabled = false
	gs.WAFParanoiaLevel = 3
	if err := d.UpdateGlobalSettings(gs); err != nil {
		t.Fatalf("UpdateGlobalSettings error: %v", err)
	}

	updated, err := d.GetGlobalSettings()
	if err != nil {
		t.Fatalf("GetGlobalSettings error: %v", err)
	}
	if updated.WAFEnabled {
		t.Error("WAFEnabled should be false")
	}
	if updated.WAFParanoiaLevel != 3 {
		t.Errorf("expected WAFParanoiaLevel 3, got %d", updated.WAFParanoiaLevel)
	}
}

func TestGetGlobalSettings_DefaultsWhenEmpty(t *testing.T) {
	d := newTestDB(t) // no seed → no row in global_settings
	gs, err := d.GetGlobalSettings()
	if err != nil {
		t.Fatalf("GetGlobalSettings error: %v", err)
	}
	if gs == nil {
		t.Fatal("expected default global settings, got nil")
	}
	if !gs.WAFEnabled {
		t.Error("default WAFEnabled should be true")
	}
}

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

func TestListConfigSchema(t *testing.T) {
	d := newSeededDB(t)

	schema, err := d.ListConfigSchema()
	if err != nil {
		t.Fatalf("ListConfigSchema error: %v", err)
	}
	if len(schema) == 0 {
		t.Error("expected schema rows after seed")
	}
	// Check that the required params are present
	found := map[string]bool{}
	for _, s := range schema {
		found[s.ParamName] = true
	}
	for _, required := range []string{"name", "subdomain", "upstream", "waf_paranoia_level"} {
		if !found[required] {
			t.Errorf("expected schema param %q not found", required)
		}
	}
}

func TestGetConfigSchemaMap(t *testing.T) {
	d := newSeededDB(t)

	m, err := d.GetConfigSchemaMap()
	if err != nil {
		t.Fatalf("GetConfigSchemaMap error: %v", err)
	}
	if s, ok := m["upstream"]; !ok || s.ParamType != "url" {
		t.Errorf("expected 'upstream' schema with type 'url', got %v", m["upstream"])
	}
}

// ---------------------------------------------------------------------------
// ensure temp files do not pollute the working directory
// ---------------------------------------------------------------------------

func TestTempFilesAreCleaned(t *testing.T) {
	// Confirm that our test helpers use t.TempDir() so nothing leaks.
	cwd, _ := os.Getwd()
	entries, _ := os.ReadDir(cwd)
	for _, e := range entries {
		if e.Name() == "test.db" {
			t.Error("test.db found in working directory — temp files are leaking")
		}
	}
}
