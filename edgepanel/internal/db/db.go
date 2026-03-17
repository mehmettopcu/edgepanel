package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/mehmettopcu/edgepanel/internal/models"
	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func New(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	conn.SetMaxOpenConns(1)
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    subdomain TEXT UNIQUE NOT NULL,
    upstream TEXT NOT NULL,
    maintenance_enabled BOOLEAN NOT NULL DEFAULT 0,
    maintenance_mode TEXT NOT NULL DEFAULT 'global',
    maintenance_paths TEXT NOT NULL DEFAULT '',
    allowlist_bypass BOOLEAN NOT NULL DEFAULT 0,
    ip_filter_enabled BOOLEAN NOT NULL DEFAULT 0,
    ip_default_policy TEXT NOT NULL DEFAULT 'allow',
    ip_allowlist TEXT NOT NULL DEFAULT '',
    ip_denylist TEXT NOT NULL DEFAULT '',
    waf_enabled BOOLEAN NOT NULL DEFAULT 1,
    waf_paranoia_level INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    route_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
    UNIQUE(user_id, route_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(route_id) REFERENCES routes(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id INTEGER,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS global_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    waf_enabled BOOLEAN NOT NULL DEFAULT 1,
    waf_paranoia_level INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS nginx_config_schema (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    param_name TEXT UNIQUE NOT NULL,
    param_type TEXT NOT NULL CHECK(param_type IN ('boolean','integer','string','enum','cidr_list','url')),
    allowed_values TEXT NOT NULL DEFAULT '',
    min_value INTEGER,
    max_value INTEGER,
    required BOOLEAN NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`
	_, err := d.conn.Exec(schema)
	return err
}

func (d *DB) SeedInitialData() error {
	var count int
	err := d.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		_, err = d.conn.Exec("INSERT INTO users (username, password_hash, is_active) VALUES (?, ?, 1)", "admin", string(hash))
		if err != nil {
			return err
		}
		log.Println("Created default admin user (username: admin, password: admin)")
	}

	var gsCount int
	err = d.conn.QueryRow("SELECT COUNT(*) FROM global_settings").Scan(&gsCount)
	if err != nil {
		return err
	}
	if gsCount == 0 {
		_, err = d.conn.Exec("INSERT INTO global_settings (waf_enabled, waf_paranoia_level) VALUES (1, 1)")
		if err != nil {
			return err
		}
	}

	var routeCount int
	err = d.conn.QueryRow("SELECT COUNT(*) FROM routes").Scan(&routeCount)
	if err != nil {
		return err
	}
	if routeCount == 0 {
		routes := []struct{ name, subdomain, upstream string }{
			{"app1", "app1.localtest.me", "http://backend1:8080"},
			{"app2", "app2.localtest.me", "http://backend2:8080"},
		}
		for _, r := range routes {
			_, err = d.conn.Exec(
				"INSERT INTO routes (name, subdomain, upstream, waf_enabled, waf_paranoia_level) VALUES (?, ?, ?, 1, 1)",
				r.name, r.subdomain, r.upstream,
			)
			if err != nil {
				return err
			}
		}
		log.Println("Seeded example routes")
	}

	if err := d.seedConfigSchema(); err != nil {
		return err
	}

	return nil
}

// seedConfigSchema inserts the parameter schema definitions on first run.
// Uses INSERT OR IGNORE so re-runs are safe.
func (d *DB) seedConfigSchema() error {
	type schemaRow struct {
		name    string
		ptype   string
		allowed string
		minVal  interface{}
		maxVal  interface{}
		req     int
		desc    string
	}
	rows := []schemaRow{
		{"name", "string", "", nil, nil, 1, "Unique name for the route"},
		{"subdomain", "string", "", nil, nil, 1, "Subdomain the route listens on (e.g. app1.example.com)"},
		{"upstream", "url", "", nil, nil, 1, "Backend upstream URL (http/https + host + optional port/path)"},
		{"maintenance_enabled", "boolean", "", nil, nil, 0, "Whether maintenance mode is active for this route"},
		{"maintenance_mode", "enum", `["global","path"]`, nil, nil, 0, "global: all requests return 503; path: only listed path prefixes return 503"},
		{"maintenance_paths", "string", "", nil, nil, 0, "Newline-separated path prefixes for path-mode maintenance"},
		{"allowlist_bypass", "boolean", "", nil, nil, 0, "Allowlisted IPs bypass maintenance mode when enabled"},
		{"ip_filter_enabled", "boolean", "", nil, nil, 0, "Whether IP-based filtering is active"},
		{"ip_default_policy", "enum", `["allow","deny"]`, nil, nil, 0, "Default policy when no IP list rule matches"},
		{"ip_allowlist", "cidr_list", "", nil, nil, 0, "Newline-separated IPv4/IPv6 CIDRs to explicitly allow"},
		{"ip_denylist", "cidr_list", "", nil, nil, 0, "Newline-separated IPv4/IPv6 CIDRs to explicitly deny"},
		{"waf_enabled", "boolean", "", nil, nil, 0, "Enable ModSecurity WAF for this route"},
		{"waf_paranoia_level", "integer", "", 1, 4, 0, "OWASP CRS paranoia level (1=low false-positive risk, 4=strict)"},
	}
	for _, row := range rows {
		_, err := d.conn.Exec(`
			INSERT OR IGNORE INTO nginx_config_schema
				(param_name, param_type, allowed_values, min_value, max_value, required, description)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.name, row.ptype, row.allowed, row.minVal, row.maxVal, row.req, row.desc,
		)
		if err != nil {
			return fmt.Errorf("seed schema %s: %w", row.name, err)
		}
	}
	return nil
}

func (d *DB) GetUserByUsername(username string) (*models.User, error) {
	u := &models.User{}
	err := d.conn.QueryRow(
		"SELECT id, username, password_hash, is_active, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsActive, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *DB) GetUserByID(id int64) (*models.User, error) {
	u := &models.User{}
	err := d.conn.QueryRow(
		"SELECT id, username, password_hash, is_active, created_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsActive, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *DB) ListUsers() ([]*models.User, error) {
	rows, err := d.conn.Query("SELECT id, username, password_hash, is_active, created_at FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsActive, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (d *DB) CreateUser(username, passwordHash string) (*models.User, error) {
	res, err := d.conn.Exec(
		"INSERT INTO users (username, password_hash, is_active) VALUES (?, ?, 1)",
		username, passwordHash,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetUserByID(id)
}

func (d *DB) UpdateUser(id int64, username string, isActive bool, passwordHash string) error {
	if passwordHash != "" {
		_, err := d.conn.Exec(
			"UPDATE users SET username=?, is_active=?, password_hash=? WHERE id=?",
			username, isActive, passwordHash, id,
		)
		return err
	}
	_, err := d.conn.Exec(
		"UPDATE users SET username=?, is_active=? WHERE id=?",
		username, isActive, id,
	)
	return err
}

func (d *DB) ListRoutes() ([]*models.Route, error) {
	rows, err := d.conn.Query(`SELECT id, name, subdomain, upstream, maintenance_enabled, maintenance_mode,
		maintenance_paths, allowlist_bypass, ip_filter_enabled, ip_default_policy,
		ip_allowlist, ip_denylist, waf_enabled, waf_paranoia_level, created_at, updated_at
		FROM routes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

func (d *DB) ListRoutesByUserID(userID int64) ([]*models.Route, error) {
	rows, err := d.conn.Query(`SELECT r.id, r.name, r.subdomain, r.upstream, r.maintenance_enabled, r.maintenance_mode,
		r.maintenance_paths, r.allowlist_bypass, r.ip_filter_enabled, r.ip_default_policy,
		r.ip_allowlist, r.ip_denylist, r.waf_enabled, r.waf_paranoia_level, r.created_at, r.updated_at
		FROM routes r
		JOIN assignments a ON a.route_id = r.id
		WHERE a.user_id = ?
		ORDER BY r.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

func scanRoutes(rows *sql.Rows) ([]*models.Route, error) {
	var routes []*models.Route
	for rows.Next() {
		r := &models.Route{}
		if err := rows.Scan(&r.ID, &r.Name, &r.Subdomain, &r.Upstream,
			&r.MaintenanceEnabled, &r.MaintenanceMode, &r.MaintenancePaths, &r.AllowlistBypass,
			&r.IPFilterEnabled, &r.IPDefaultPolicy, &r.IPAllowlist, &r.IPDenylist,
			&r.WAFEnabled, &r.WAFParanoiaLevel, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

func (d *DB) GetRouteByID(id int64) (*models.Route, error) {
	r := &models.Route{}
	err := d.conn.QueryRow(`SELECT id, name, subdomain, upstream, maintenance_enabled, maintenance_mode,
		maintenance_paths, allowlist_bypass, ip_filter_enabled, ip_default_policy,
		ip_allowlist, ip_denylist, waf_enabled, waf_paranoia_level, created_at, updated_at
		FROM routes WHERE id = ?`, id).Scan(
		&r.ID, &r.Name, &r.Subdomain, &r.Upstream,
		&r.MaintenanceEnabled, &r.MaintenanceMode, &r.MaintenancePaths, &r.AllowlistBypass,
		&r.IPFilterEnabled, &r.IPDefaultPolicy, &r.IPAllowlist, &r.IPDenylist,
		&r.WAFEnabled, &r.WAFParanoiaLevel, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (d *DB) CreateRoute(r *models.Route) (*models.Route, error) {
	res, err := d.conn.Exec(`INSERT INTO routes (name, subdomain, upstream, maintenance_enabled, maintenance_mode,
		maintenance_paths, allowlist_bypass, ip_filter_enabled, ip_default_policy,
		ip_allowlist, ip_denylist, waf_enabled, waf_paranoia_level)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Name, r.Subdomain, r.Upstream, r.MaintenanceEnabled, r.MaintenanceMode,
		r.MaintenancePaths, r.AllowlistBypass, r.IPFilterEnabled, r.IPDefaultPolicy,
		r.IPAllowlist, r.IPDenylist, r.WAFEnabled, r.WAFParanoiaLevel,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetRouteByID(id)
}

func (d *DB) UpdateRoute(r *models.Route) error {
	r.UpdatedAt = time.Now()
	_, err := d.conn.Exec(`UPDATE routes SET name=?, subdomain=?, upstream=?,
		maintenance_enabled=?, maintenance_mode=?, maintenance_paths=?, allowlist_bypass=?,
		ip_filter_enabled=?, ip_default_policy=?, ip_allowlist=?, ip_denylist=?,
		waf_enabled=?, waf_paranoia_level=?, updated_at=?
		WHERE id=?`,
		r.Name, r.Subdomain, r.Upstream,
		r.MaintenanceEnabled, r.MaintenanceMode, r.MaintenancePaths, r.AllowlistBypass,
		r.IPFilterEnabled, r.IPDefaultPolicy, r.IPAllowlist, r.IPDenylist,
		r.WAFEnabled, r.WAFParanoiaLevel, r.UpdatedAt,
		r.ID,
	)
	return err
}

func (d *DB) UpsertAssignment(userID, routeID int64, role string) error {
	_, err := d.conn.Exec(`INSERT INTO assignments (user_id, route_id, role) VALUES (?,?,?)
		ON CONFLICT(user_id, route_id) DO UPDATE SET role=excluded.role`,
		userID, routeID, role,
	)
	return err
}

func (d *DB) GetAssignment(userID, routeID int64) (*models.Assignment, error) {
	a := &models.Assignment{}
	err := d.conn.QueryRow("SELECT id, user_id, route_id, role FROM assignments WHERE user_id=? AND route_id=?",
		userID, routeID).Scan(&a.ID, &a.UserID, &a.RouteID, &a.Role)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// IsAdmin returns true for the first-created user (id=1) or any user
// with at least one admin-role assignment.
func (d *DB) IsAdmin(userID int64) bool {
	var id int64
	err := d.conn.QueryRow("SELECT id FROM users WHERE id=1 AND id=?", userID).Scan(&id)
	if err == nil {
		return true
	}
	var count int
	d.conn.QueryRow("SELECT COUNT(*) FROM assignments WHERE user_id=? AND role='admin'", userID).Scan(&count)
	return count > 0
}

func (d *DB) CreateAuditLog(userID *int64, username, action, resourceType string, resourceID *int64, details string) error {
	_, err := d.conn.Exec(
		"INSERT INTO audit_logs (user_id, username, action, resource_type, resource_id, details) VALUES (?,?,?,?,?,?)",
		userID, username, action, resourceType, resourceID, details,
	)
	return err
}

func (d *DB) ListAuditLogs(limit int) ([]*models.AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.conn.Query(
		"SELECT id, user_id, username, action, resource_type, resource_id, details, created_at FROM audit_logs ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []*models.AuditLog
	for rows.Next() {
		l := &models.AuditLog{}
		if err := rows.Scan(&l.ID, &l.UserID, &l.Username, &l.Action, &l.ResourceType, &l.ResourceID, &l.Details, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func (d *DB) GetGlobalSettings() (*models.GlobalSettings, error) {
	gs := &models.GlobalSettings{}
	err := d.conn.QueryRow("SELECT id, waf_enabled, waf_paranoia_level FROM global_settings LIMIT 1").Scan(&gs.ID, &gs.WAFEnabled, &gs.WAFParanoiaLevel)
	if err == sql.ErrNoRows {
		return &models.GlobalSettings{WAFEnabled: true, WAFParanoiaLevel: 1}, nil
	}
	return gs, err
}

func (d *DB) UpdateGlobalSettings(gs *models.GlobalSettings) error {
	_, err := d.conn.Exec("UPDATE global_settings SET waf_enabled=?, waf_paranoia_level=? WHERE id=?",
		gs.WAFEnabled, gs.WAFParanoiaLevel, gs.ID)
	return err
}

// ListConfigSchema returns all rows from nginx_config_schema.
func (d *DB) ListConfigSchema() ([]*models.NginxConfigSchema, error) {
	rows, err := d.conn.Query(
		`SELECT id, param_name, param_type, allowed_values, min_value, max_value, required, description
		 FROM nginx_config_schema ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*models.NginxConfigSchema
	for rows.Next() {
		s := &models.NginxConfigSchema{}
		if err := rows.Scan(&s.ID, &s.ParamName, &s.ParamType,
			&s.AllowedValues, &s.MinValue, &s.MaxValue, &s.Required, &s.Description); err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, rows.Err()
}

// GetConfigSchemaMap returns a map of param_name → NginxConfigSchema for fast lookups.
func (d *DB) GetConfigSchemaMap() (map[string]*models.NginxConfigSchema, error) {
	list, err := d.ListConfigSchema()
	if err != nil {
		return nil, err
	}
	m := make(map[string]*models.NginxConfigSchema, len(list))
	for _, s := range list {
		m[s.ParamName] = s
	}
	return m, nil
}
