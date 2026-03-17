package nginx_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mehmettopcu/edgepanel/internal/models"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestGenerator(t *testing.T) (*nginx.Generator, string) {
	t.Helper()
	dir := t.TempDir()
	gen := nginx.New(dir, "nginx") // binary name doesn't matter for pure-generate tests
	return gen, dir
}

func validRoute(id int64) *models.Route {
	return &models.Route{
		ID:               id,
		Name:             "app1",
		Subdomain:        "app1.example.com",
		Upstream:         "http://backend1:8080",
		WAFEnabled:       false,
		WAFParanoiaLevel: 1,
		MaintenanceMode:  "global",
		IPDefaultPolicy:  "allow",
	}
}

func defaultSettings() *models.GlobalSettings {
	return &models.GlobalSettings{WAFEnabled: true, WAFParanoiaLevel: 1}
}

// ---------------------------------------------------------------------------
// Generate — happy-path
// ---------------------------------------------------------------------------

func TestGenerate_CreatesExpectedFiles(t *testing.T) {
	gen, dir := newTestGenerator(t)

	routes := []*models.Route{validRoute(1), validRoute(2)}
	if err := gen.Generate(routes, defaultSettings()); err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	expectedFiles := []string{
		filepath.Join(dir, "routes", "1.conf"),
		filepath.Join(dir, "routes", "2.conf"),
		filepath.Join(dir, "iplists", "1.allow"),
		filepath.Join(dir, "iplists", "1.deny"),
		filepath.Join(dir, "iplists", "2.allow"),
		filepath.Join(dir, "iplists", "2.deny"),
		filepath.Join(dir, "waf.conf"),
	}

	for _, f := range expectedFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("expected file not found: %s", f)
		}
	}
}

func TestGenerate_EmptyRoutes(t *testing.T) {
	gen, dir := newTestGenerator(t)

	if err := gen.Generate(nil, defaultSettings()); err != nil {
		t.Fatalf("Generate with empty routes should not error: %v", err)
	}
	// waf.conf should still be written
	wafPath := filepath.Join(dir, "waf.conf")
	if _, err := os.Stat(wafPath); os.IsNotExist(err) {
		t.Error("waf.conf should exist even when routes list is empty")
	}
}

// ---------------------------------------------------------------------------
// NGINX config content assertions
// ---------------------------------------------------------------------------

func TestGenerate_RouteConf_BasicProxy(t *testing.T) {
	gen, dir := newTestGenerator(t)
	r := validRoute(5)
	if err := gen.Generate([]*models.Route{r}, defaultSettings()); err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	confBytes, err := os.ReadFile(filepath.Join(dir, "routes", "5.conf"))
	if err != nil {
		t.Fatalf("read conf: %v", err)
	}
	conf := string(confBytes)

	if !strings.Contains(conf, "server_name app1.example.com") {
		t.Error("config should contain server_name directive")
	}
	if !strings.Contains(conf, "proxy_pass http://backend1:8080") {
		t.Error("config should contain proxy_pass directive")
	}
	if strings.Contains(conf, "modsecurity on") {
		t.Error("modsecurity should NOT be on when WAFEnabled=false")
	}
}

func TestGenerate_RouteConf_WAFEnabled(t *testing.T) {
	gen, dir := newTestGenerator(t)
	r := validRoute(6)
	r.WAFEnabled = true

	if err := gen.Generate([]*models.Route{r}, defaultSettings()); err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	confBytes, _ := os.ReadFile(filepath.Join(dir, "routes", "6.conf"))
	conf := string(confBytes)

	if !strings.Contains(conf, "modsecurity on") {
		t.Error("expected 'modsecurity on' when WAFEnabled=true")
	}
}

func TestGenerate_RouteConf_MaintenanceEnabled_Global(t *testing.T) {
	gen, dir := newTestGenerator(t)
	r := validRoute(7)
	r.MaintenanceEnabled = true
	r.MaintenanceMode = "global"
	r.AllowlistBypass = false

	if err := gen.Generate([]*models.Route{r}, defaultSettings()); err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	confBytes, _ := os.ReadFile(filepath.Join(dir, "routes", "7.conf"))
	conf := string(confBytes)

	if !strings.Contains(conf, "return 503") {
		t.Error("expected 'return 503' in global maintenance config")
	}
}

func TestGenerate_RouteConf_IPFilter(t *testing.T) {
	gen, dir := newTestGenerator(t)
	r := validRoute(8)
	r.IPFilterEnabled = true
	r.IPDefaultPolicy = "deny"
	r.IPAllowlist = "192.168.1.0/24\n10.0.0.1"
	r.IPDenylist = "1.2.3.4"

	if err := gen.Generate([]*models.Route{r}, defaultSettings()); err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Check route conf contains includes
	confBytes, _ := os.ReadFile(filepath.Join(dir, "routes", "8.conf"))
	conf := string(confBytes)
	if !strings.Contains(conf, "iplists/8.allow") {
		t.Error("expected allowlist include in config")
	}
	if !strings.Contains(conf, "iplists/8.deny") {
		t.Error("expected denylist include in config")
	}
	if !strings.Contains(conf, "deny all") {
		t.Error("expected 'deny all' for deny default policy")
	}

	// Check allow file content
	allowBytes, _ := os.ReadFile(filepath.Join(dir, "iplists", "8.allow"))
	allow := string(allowBytes)
	if !strings.Contains(allow, "allow 192.168.1.0/24;") {
		t.Errorf("expected allow 192.168.1.0/24; in allow file, got: %s", allow)
	}
	if !strings.Contains(allow, "allow 10.0.0.1;") {
		t.Errorf("expected allow 10.0.0.1; in allow file, got: %s", allow)
	}

	// Check deny file content
	denyBytes, _ := os.ReadFile(filepath.Join(dir, "iplists", "8.deny"))
	deny := string(denyBytes)
	if !strings.Contains(deny, "deny 1.2.3.4;") {
		t.Errorf("expected deny 1.2.3.4; in deny file, got: %s", deny)
	}
}

// ---------------------------------------------------------------------------
// WAF config
// ---------------------------------------------------------------------------

func TestGenerate_WafConf_Content(t *testing.T) {
	gen, dir := newTestGenerator(t)
	settings := &models.GlobalSettings{WAFEnabled: true, WAFParanoiaLevel: 3}

	if err := gen.Generate(nil, settings); err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	wafBytes, _ := os.ReadFile(filepath.Join(dir, "waf.conf"))
	waf := string(wafBytes)

	if !strings.Contains(waf, "WAF Paranoia Level: 3") {
		t.Errorf("expected paranoia level 3 in waf.conf, got: %s", waf)
	}
}

// ---------------------------------------------------------------------------
// GenerateAndTest — staging not promoted when nginx -t unavailable
// ---------------------------------------------------------------------------

func TestGenerateAndTest_StagingDirCleanedUp(t *testing.T) {
	gen, dir := newTestGenerator(t)

	// Use a non-existent nginx binary so Test() will fail; we just want to
	// confirm the staging directory is cleaned up regardless.
	gen.NginxBinary = "/nonexistent/nginx"

	routes := []*models.Route{validRoute(1)}
	_, err := gen.GenerateAndTest(routes, defaultSettings())
	// Error expected because nginx doesn't exist
	if err == nil {
		t.Log("nginx binary happened to succeed (unlikely in CI), skipping cleanup check")
		return
	}

	stagingDir := dir + ".staging"
	if _, statErr := os.Stat(stagingDir); !os.IsNotExist(statErr) {
		t.Error("staging directory should be cleaned up after failed GenerateAndTest")
	}
}
