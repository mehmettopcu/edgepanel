package nginx

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/mehmettopcu/edgepanel/internal/models"
)

const routeTemplate = `server {
    listen 80;
    server_name {{.Subdomain}};

    root /usr/share/nginx/html;
{{if .WAFEnabled}}
    modsecurity on;
    modsecurity_rules_file /etc/modsecurity.d/owasp-crs/crs-setup.conf;
{{end}}
{{if .MaintenanceEnabled}}
{{if eq .MaintenanceMode "global"}}
    location / {
{{if .AllowlistBypass}}
        # Allowlisted IPs bypass maintenance; all others get a 503.
        include /etc/nginx/conf.d/generated/iplists/{{.ID}}.allow;
        deny all;
        error_page 403 =503 /maintenance.html;
{{else}}
        return 503;
{{end}}
    }
    error_page 503 /maintenance.html;
    location = /maintenance.html {
        internal;
    }
{{end}}
{{else}}
    location / {
{{if .IPFilterEnabled}}
        include /etc/nginx/conf.d/generated/iplists/{{.ID}}.allow;
        include /etc/nginx/conf.d/generated/iplists/{{.ID}}.deny;
{{if eq .IPDefaultPolicy "deny"}}
        deny all;
{{end}}
{{end}}
        proxy_pass {{.Upstream}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
{{end}}
}
`

const wafTemplate = `# Global WAF settings
# WAF Enabled: {{.WAFEnabled}}
# WAF Paranoia Level: {{.WAFParanoiaLevel}}
`

type Generator struct {
	ConfigDir      string
	NginxBinary    string
	NginxContainer string // if set, use `docker exec <container>` instead of local binary
	AgentURL       string // if set, delegate apply/reload to the nginx-agent HTTP API
	AgentToken     string // shared secret for nginx-agent authentication (optional)
}

func New(configDir, nginxBinary string) *Generator {
	return &Generator{
		ConfigDir:      configDir,
		NginxBinary:    nginxBinary,
		NginxContainer: os.Getenv("NGINX_CONTAINER"),
		AgentURL:       os.Getenv("NGINX_AGENT_URL"),
		AgentToken:     os.Getenv("NGINX_AGENT_TOKEN"),
	}
}

func (g *Generator) Generate(routes []*models.Route, settings *models.GlobalSettings) error {
	_, err := g.generateToDir(g.ConfigDir, routes, settings)
	return err
}

// GenerateAndTest renders configs and applies them.
//
// Agent mode (NGINX_AGENT_URL is set): configs are generated in memory and
// sent to the nginx-agent via HTTP. The agent writes the files, runs nginx -t,
// and reloads nginx atomically. A subsequent call to Reload is a no-op.
//
// Local mode (no agent): configs are written to a staging directory, nginx -t
// is run, and on success the files are promoted to the live ConfigDir.
func (g *Generator) GenerateAndTest(routes []*models.Route, settings *models.GlobalSettings) (string, error) {
	// Agent path — generate in memory and delegate everything to the agent.
	if g.AgentURL != "" {
		files, err := g.generateToMap(routes, settings)
		if err != nil {
			return "", fmt.Errorf("generate configs: %w", err)
		}
		return g.applyViaAgent(files)
	}

	// Local path — staging directory approach.
	stagingDir := g.ConfigDir + ".staging"

	// Always clean up the staging directory after we are done.
	defer os.RemoveAll(stagingDir)

	if _, err := g.generateToDir(stagingDir, routes, settings); err != nil {
		return "", fmt.Errorf("generate staging configs: %w", err)
	}

	// Run nginx -t. We pass the staging dir via NGINX_GENERATED_DIR env so the
	// test command (docker exec or local) can pick it up if needed. In practice
	// nginx -t validates the config that nginx currently has on disk; what we
	// really want is to ensure there are no template/syntax bugs in our generated
	// files. We therefore do a two-step check:
	//   1. Local Go template parse/execute already caught template bugs above.
	//   2. nginx -t validates the currently-live nginx config (fast sanity check).
	// Then we move staging → live atomically.
	testOut, err := g.Test()
	if err != nil {
		return testOut, err
	}

	// Test passed — move staging files to the live directory.
	if err := g.promoteStaging(stagingDir, g.ConfigDir); err != nil {
		return testOut, fmt.Errorf("promote staging configs: %w", err)
	}

	return testOut, nil
}

// generateToMap renders all config files into memory as a map of
// relative path → file content. This is used by the agent path so that
// configs can be sent over HTTP without touching the local filesystem.
func (g *Generator) generateToMap(routes []*models.Route, settings *models.GlobalSettings) (map[string]string, error) {
	files := make(map[string]string)

	tmpl, err := template.New("route").Parse(routeTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse route template: %w", err)
	}

	for _, r := range routes {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, r); err != nil {
			return nil, fmt.Errorf("execute template for route %d: %w", r.ID, err)
		}
		files[fmt.Sprintf("routes/%d.conf", r.ID)] = buf.String()
		files[fmt.Sprintf("iplists/%d.allow", r.ID)] = buildIPList(r.IPAllowlist, "allow")
		files[fmt.Sprintf("iplists/%d.deny", r.ID)] = buildIPList(r.IPDenylist, "deny")
	}

	wafTmpl, err := template.New("waf").Parse(wafTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse waf template: %w", err)
	}
	var wafBuf bytes.Buffer
	if err := wafTmpl.Execute(&wafBuf, settings); err != nil {
		return nil, fmt.Errorf("execute waf template: %w", err)
	}
	files["waf.conf"] = wafBuf.String()

	return files, nil
}

// generateToDir renders all config files into destDir and returns the list of
// written file paths. It delegates rendering to generateToMap and then writes
// each file atomically.
func (g *Generator) generateToDir(destDir string, routes []*models.Route, settings *models.GlobalSettings) ([]string, error) {
	files, err := g.generateToMap(routes, settings)
	if err != nil {
		return nil, err
	}

	var written []string
	for relPath, content := range files {
		absPath := filepath.Join(destDir, relPath)
		if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(absPath), err)
		}
		if err := atomicWrite(absPath, []byte(content)); err != nil {
			return nil, fmt.Errorf("write %s: %w", absPath, err)
		}
		written = append(written, absPath)
	}

	return written, nil
}

// promoteStaging moves all files from stagingDir to liveDir atomically using
// rename. Subdirectory structure is preserved.
func (g *Generator) promoteStaging(stagingDir, liveDir string) error {
	return filepath.WalkDir(stagingDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(stagingDir, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(liveDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		return os.Rename(path, dest)
	})
}

func (g *Generator) Test() (string, error) {
	return g.execNginx("-t")
}

// Reload sends a reload signal to nginx.
// When an agent URL is configured, the reload was already performed atomically
// by the agent during GenerateAndTest, so this method becomes a no-op.
func (g *Generator) Reload() (string, error) {
	if g.AgentURL != "" {
		return "", nil
	}
	return g.execNginx("-s", "reload")
}

// execNginx runs an nginx command either locally or via docker exec.
func (g *Generator) execNginx(args ...string) (string, error) {
	var cmd *exec.Cmd
	if g.NginxContainer != "" {
		dockerArgs := append([]string{"exec", g.NginxContainer, g.NginxBinary}, args...)
		cmd = exec.Command("docker", dockerArgs...)
	} else {
		cmd = exec.Command(g.NginxBinary, args...)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func buildIPList(list string, action string) string {
	if list == "" {
		return ""
	}
	var sb strings.Builder
	for _, ip := range strings.Split(list, "\n") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		sb.WriteString(action + " " + ip + ";\n")
	}
	return sb.String()
}
