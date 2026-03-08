package validation_test

import (
	"testing"

	"github.com/mehmettopcu/edgepanel/internal/models"
	"github.com/mehmettopcu/edgepanel/internal/validation"
)

// buildSchema returns a minimal schema map seeded with the same values as
// the DB seed in db.SeedInitialData so tests are self-contained.
func buildSchema() map[string]*models.NginxConfigSchema {
	one, four := 1, 4
	return map[string]*models.NginxConfigSchema{
		"name":               {ParamName: "name", ParamType: "string", Required: true},
		"subdomain":          {ParamName: "subdomain", ParamType: "string", Required: true},
		"upstream":           {ParamName: "upstream", ParamType: "url", Required: true},
		"maintenance_mode":   {ParamName: "maintenance_mode", ParamType: "enum", AllowedValues: `["global","path"]`},
		"ip_default_policy":  {ParamName: "ip_default_policy", ParamType: "enum", AllowedValues: `["allow","deny"]`},
		"ip_allowlist":       {ParamName: "ip_allowlist", ParamType: "cidr_list"},
		"ip_denylist":        {ParamName: "ip_denylist", ParamType: "cidr_list"},
		"waf_paranoia_level": {ParamName: "waf_paranoia_level", ParamType: "integer", MinValue: &one, MaxValue: &four},
	}
}

func validRoute() *models.Route {
	return &models.Route{
		Name:             "app1",
		Subdomain:        "app1.localtest.me",
		Upstream:         "http://backend1:8080",
		MaintenanceMode:  "global",
		IPDefaultPolicy:  "allow",
		WAFParanoiaLevel: 1,
	}
}

func TestValidateRoute_Valid(t *testing.T) {
	errs := validation.ValidateRoute(validRoute(), buildSchema())
	if errs.HasErrors() {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestValidateRoute_EmptyName(t *testing.T) {
	r := validRoute()
	r.Name = ""
	errs := validation.ValidateRoute(r, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for empty name")
	}
	found := false
	for _, e := range errs {
		if e.Field == "name" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected field 'name' in errors, got: %v", errs)
	}
}

func TestValidateRoute_InvalidUpstream(t *testing.T) {
	r := validRoute()
	r.Upstream = "not-a-url"
	errs := validation.ValidateRoute(r, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for invalid upstream")
	}
	found := false
	for _, e := range errs {
		if e.Field == "upstream" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected field 'upstream' in errors, got: %v", errs)
	}
}

func TestValidateRoute_InvalidMaintenanceMode(t *testing.T) {
	r := validRoute()
	r.MaintenanceMode = "invalid"
	errs := validation.ValidateRoute(r, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for invalid maintenance_mode")
	}
	found := false
	for _, e := range errs {
		if e.Field == "maintenance_mode" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected field 'maintenance_mode' in errors, got: %v", errs)
	}
}

func TestValidateRoute_InvalidIPDefaultPolicy(t *testing.T) {
	r := validRoute()
	r.IPDefaultPolicy = "block"
	errs := validation.ValidateRoute(r, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for invalid ip_default_policy")
	}
}

func TestValidateRoute_WAFParanoiaLevelOutOfRange(t *testing.T) {
	r := validRoute()
	r.WAFParanoiaLevel = 5
	errs := validation.ValidateRoute(r, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for waf_paranoia_level=5")
	}
	found := false
	for _, e := range errs {
		if e.Field == "waf_paranoia_level" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected field 'waf_paranoia_level' in errors, got: %v", errs)
	}
}

func TestValidateRoute_InvalidCIDR(t *testing.T) {
	r := validRoute()
	r.IPAllowlist = "not-an-ip\n192.168.1.0/24"
	errs := validation.ValidateRoute(r, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for invalid CIDR")
	}
	found := false
	for _, e := range errs {
		if e.Field == "ip_allowlist" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected field 'ip_allowlist' in errors, got: %v", errs)
	}
}

func TestValidateRoute_ValidCIDRList(t *testing.T) {
	r := validRoute()
	r.IPAllowlist = "192.168.1.0/24\n10.0.0.1\n2001:db8::/32"
	errs := validation.ValidateRoute(r, buildSchema())
	if errs.HasErrors() {
		t.Fatalf("expected no errors for valid CIDR list, got: %v", errs)
	}
}

func TestValidateRoute_NilSchema(t *testing.T) {
	// Without schema map the validator falls back to built-in rules.
	r := validRoute()
	errs := validation.ValidateRoute(r, nil)
	if errs.HasErrors() {
		t.Fatalf("expected no errors with nil schema, got: %v", errs)
	}
}

func TestValidateRoute_NilSchema_InvalidUpstream(t *testing.T) {
	r := validRoute()
	r.Upstream = "ftp://not-http"
	errs := validation.ValidateRoute(r, nil)
	if !errs.HasErrors() {
		t.Fatal("expected upstream validation error even with nil schema")
	}
}

func TestValidateGlobalSettings_Valid(t *testing.T) {
	errs := validation.ValidateGlobalSettings(2, buildSchema())
	if errs.HasErrors() {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestValidateGlobalSettings_Invalid(t *testing.T) {
	errs := validation.ValidateGlobalSettings(0, buildSchema())
	if !errs.HasErrors() {
		t.Fatal("expected validation error for paranoia_level=0")
	}
}
