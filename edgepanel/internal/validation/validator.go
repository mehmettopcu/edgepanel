// Package validation provides schema-driven validation for nginx config parameters.
// The schema is loaded from the DB (nginx_config_schema table) and used to check
// each field of a Route before it is written to the database.
package validation

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/mehmettopcu/edgepanel/internal/models"
)

// FieldError describes a validation failure for a single field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a slice of FieldErrors that also satisfies the error interface.
type ValidationErrors []FieldError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

func (ve ValidationErrors) HasErrors() bool { return len(ve) > 0 }

// ValidateRoute checks every field of r against the provided schema map.
// If schemaMap is nil or empty the function falls back to built-in rules only.
func ValidateRoute(r *models.Route, schemaMap map[string]*models.NginxConfigSchema) ValidationErrors {
	var errs ValidationErrors

	check := func(field, value string) *models.NginxConfigSchema {
		if schemaMap == nil {
			return nil
		}
		return schemaMap[field]
	}

	// --- name ---
	if s := check("name", r.Name); s != nil {
		errs = append(errs, validateString("name", r.Name, s)...)
	} else if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, FieldError{"name", "must not be empty"})
	}

	// --- subdomain ---
	if s := check("subdomain", r.Subdomain); s != nil {
		errs = append(errs, validateString("subdomain", r.Subdomain, s)...)
	} else if strings.TrimSpace(r.Subdomain) == "" {
		errs = append(errs, FieldError{"subdomain", "must not be empty"})
	}

	// --- upstream ---
	if s := check("upstream", r.Upstream); s != nil {
		errs = append(errs, validateURL("upstream", r.Upstream, s)...)
	} else {
		errs = append(errs, validateURLRaw("upstream", r.Upstream)...)
	}

	// --- maintenance_mode ---
	if s := check("maintenance_mode", r.MaintenanceMode); s != nil {
		errs = append(errs, validateEnum("maintenance_mode", r.MaintenanceMode, s)...)
	} else if r.MaintenanceMode != "" && r.MaintenanceMode != "global" && r.MaintenanceMode != "path" {
		errs = append(errs, FieldError{"maintenance_mode", `must be "global" or "path"`})
	}

	// --- ip_default_policy ---
	if s := check("ip_default_policy", r.IPDefaultPolicy); s != nil {
		errs = append(errs, validateEnum("ip_default_policy", r.IPDefaultPolicy, s)...)
	} else if r.IPDefaultPolicy != "" && r.IPDefaultPolicy != "allow" && r.IPDefaultPolicy != "deny" {
		errs = append(errs, FieldError{"ip_default_policy", `must be "allow" or "deny"`})
	}

	// --- ip_allowlist ---
	if r.IPAllowlist != "" {
		if s := check("ip_allowlist", r.IPAllowlist); s != nil {
			errs = append(errs, validateCIDRList("ip_allowlist", r.IPAllowlist, s)...)
		} else {
			errs = append(errs, validateCIDRListRaw("ip_allowlist", r.IPAllowlist)...)
		}
	}

	// --- ip_denylist ---
	if r.IPDenylist != "" {
		if s := check("ip_denylist", r.IPDenylist); s != nil {
			errs = append(errs, validateCIDRList("ip_denylist", r.IPDenylist, s)...)
		} else {
			errs = append(errs, validateCIDRListRaw("ip_denylist", r.IPDenylist)...)
		}
	}

	// --- waf_paranoia_level ---
	if s := check("waf_paranoia_level", ""); s != nil {
		errs = append(errs, validateInteger("waf_paranoia_level", r.WAFParanoiaLevel, s)...)
	} else if r.WAFParanoiaLevel < 1 || r.WAFParanoiaLevel > 4 {
		errs = append(errs, FieldError{"waf_paranoia_level", "must be between 1 and 4"})
	}

	return errs
}

// ValidateGlobalSettings validates the global WAF settings against the schema.
func ValidateGlobalSettings(wafParanoiaLevel int, schemaMap map[string]*models.NginxConfigSchema) ValidationErrors {
	var errs ValidationErrors
	if s, ok := schemaMap["waf_paranoia_level"]; ok {
		errs = append(errs, validateInteger("waf_paranoia_level", wafParanoiaLevel, s)...)
	} else if wafParanoiaLevel < 1 || wafParanoiaLevel > 4 {
		errs = append(errs, FieldError{"waf_paranoia_level", "must be between 1 and 4"})
	}
	return errs
}

// ---------------------------------------------------------------------------
// per-type validators
// ---------------------------------------------------------------------------

func validateString(field, value string, s *models.NginxConfigSchema) ValidationErrors {
	if s.Required && strings.TrimSpace(value) == "" {
		return ValidationErrors{{field, "must not be empty"}}
	}
	return nil
}

func validateURL(field, value string, s *models.NginxConfigSchema) ValidationErrors {
	if s.Required && strings.TrimSpace(value) == "" {
		return ValidationErrors{{field, "must not be empty"}}
	}
	return validateURLRaw(field, value)
}

func validateURLRaw(field, value string) ValidationErrors {
	if strings.TrimSpace(value) == "" {
		return ValidationErrors{{field, "must not be empty"}}
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ValidationErrors{{field, "must be a valid http or https URL"}}
	}
	return nil
}

func validateEnum(field, value string, s *models.NginxConfigSchema) ValidationErrors {
	if value == "" && !s.Required {
		return nil
	}
	if s.AllowedValues == "" {
		return nil
	}
	var allowed []string
	if err := json.Unmarshal([]byte(s.AllowedValues), &allowed); err != nil {
		// schema is malformed; skip enum check
		return nil
	}
	for _, a := range allowed {
		if a == value {
			return nil
		}
	}
	return ValidationErrors{{field, fmt.Sprintf("must be one of %v", allowed)}}
}

func validateInteger(field string, value int, s *models.NginxConfigSchema) ValidationErrors {
	if s.MinValue != nil && value < *s.MinValue {
		return ValidationErrors{{field, fmt.Sprintf("must be >= %d", *s.MinValue)}}
	}
	if s.MaxValue != nil && value > *s.MaxValue {
		return ValidationErrors{{field, fmt.Sprintf("must be <= %d", *s.MaxValue)}}
	}
	return nil
}

func validateCIDRList(field, value string, _ *models.NginxConfigSchema) ValidationErrors {
	return validateCIDRListRaw(field, value)
}

func validateCIDRListRaw(field, value string) ValidationErrors {
	var errs ValidationErrors
	for i, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Accept plain IPs and CIDR notation
		if _, _, err := net.ParseCIDR(line); err != nil {
			if net.ParseIP(line) == nil {
				errs = append(errs, FieldError{
					field,
					fmt.Sprintf("line %d: %q is not a valid IP or CIDR", i+1, line),
				})
			}
		}
	}
	return errs
}
