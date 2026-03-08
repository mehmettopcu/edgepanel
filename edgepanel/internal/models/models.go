package models

import "time"

type User struct {
	ID           int64     `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	PasswordHash string    `json:"-" db:"password_hash"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type Route struct {
	ID                 int64     `json:"id" db:"id"`
	Name               string    `json:"name" db:"name"`
	Subdomain          string    `json:"subdomain" db:"subdomain"`
	Upstream           string    `json:"upstream" db:"upstream"`
	MaintenanceEnabled bool      `json:"maintenance_enabled" db:"maintenance_enabled"`
	MaintenanceMode    string    `json:"maintenance_mode" db:"maintenance_mode"`
	MaintenancePaths   string    `json:"maintenance_paths" db:"maintenance_paths"`
	AllowlistBypass    bool      `json:"allowlist_bypass" db:"allowlist_bypass"`
	IPFilterEnabled    bool      `json:"ip_filter_enabled" db:"ip_filter_enabled"`
	IPDefaultPolicy    string    `json:"ip_default_policy" db:"ip_default_policy"`
	IPAllowlist        string    `json:"ip_allowlist" db:"ip_allowlist"`
	IPDenylist         string    `json:"ip_denylist" db:"ip_denylist"`
	WAFEnabled         bool      `json:"waf_enabled" db:"waf_enabled"`
	WAFParanoiaLevel   int       `json:"waf_paranoia_level" db:"waf_paranoia_level"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

type Assignment struct {
	ID      int64  `json:"id" db:"id"`
	UserID  int64  `json:"user_id" db:"user_id"`
	RouteID int64  `json:"route_id" db:"route_id"`
	Role    string `json:"role" db:"role"`
}

type AuditLog struct {
	ID           int64     `json:"id" db:"id"`
	UserID       *int64    `json:"user_id" db:"user_id"`
	Username     string    `json:"username" db:"username"`
	Action       string    `json:"action" db:"action"`
	ResourceType string    `json:"resource_type" db:"resource_type"`
	ResourceID   *int64    `json:"resource_id" db:"resource_id"`
	Details      string    `json:"details" db:"details"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type GlobalSettings struct {
	ID               int64 `json:"id" db:"id"`
	WAFEnabled       bool  `json:"waf_enabled" db:"waf_enabled"`
	WAFParanoiaLevel int   `json:"waf_paranoia_level" db:"waf_paranoia_level"`
}

// ConfigParamType enumerates the types a schema parameter can have.
type ConfigParamType string

const (
	ParamTypeBoolean  ConfigParamType = "boolean"
	ParamTypeInteger  ConfigParamType = "integer"
	ParamTypeString   ConfigParamType = "string"
	ParamTypeEnum     ConfigParamType = "enum"
	ParamTypeCIDRList ConfigParamType = "cidr_list"
	ParamTypeURL      ConfigParamType = "url"
)

// NginxConfigSchema describes the valid values / constraints for a single
// configuration parameter. Rows are seeded once and can be updated by admins.
type NginxConfigSchema struct {
	ID            int64           `json:"id" db:"id"`
	ParamName     string          `json:"param_name" db:"param_name"`
	ParamType     ConfigParamType `json:"param_type" db:"param_type"`
	AllowedValues string          `json:"allowed_values" db:"allowed_values"` // JSON array for enum, empty otherwise
	MinValue      *int            `json:"min_value" db:"min_value"`           // for integer type
	MaxValue      *int            `json:"max_value" db:"max_value"`           // for integer type
	Required      bool            `json:"required" db:"required"`
	Description   string          `json:"description" db:"description"`
}
