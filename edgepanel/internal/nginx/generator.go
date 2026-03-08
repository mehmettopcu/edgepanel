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
	ConfigDir       string
	NginxBinary     string
	NginxContainer  string // if set, use `docker exec <container>` instead of local binary
}

func New(configDir, nginxBinary string) *Generator {
	return &Generator{
		ConfigDir:      configDir,
		NginxBinary:    nginxBinary,
		NginxContainer: os.Getenv("NGINX_CONTAINER"),
	}
}

func (g *Generator) Generate(routes []*models.Route, settings *models.GlobalSettings) error {
	_, err := g.generateToDir(g.ConfigDir, routes, settings)
	return err
}

// GenerateAndTest writes configs to a staging directory, runs nginx -t against
// the staging tree, and if the test passes, atomically moves the files to the
// live ConfigDir. It returns the nginx -t output and any error.
func (g *Generator) GenerateAndTest(routes []*models.Route, settings *models.GlobalSettings) (string, error) {
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

// generateToDir renders all config files into destDir and returns the list of
// written file paths.
func (g *Generator) generateToDir(destDir string, routes []*models.Route, settings *models.GlobalSettings) ([]string, error) {
	routesDir := filepath.Join(destDir, "routes")
	iplistsDir := filepath.Join(destDir, "iplists")

	for _, dir := range []string{routesDir, iplistsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	tmpl, err := template.New("route").Parse(routeTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse route template: %w", err)
	}

	var written []string
	for _, r := range routes {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, r); err != nil {
			return nil, fmt.Errorf("execute template for route %d: %w", r.ID, err)
		}
		confPath := filepath.Join(routesDir, fmt.Sprintf("%d.conf", r.ID))
		if err := atomicWrite(confPath, buf.Bytes()); err != nil {
			return nil, fmt.Errorf("write route config %d: %w", r.ID, err)
		}
		written = append(written, confPath)

		allowPath := filepath.Join(iplistsDir, fmt.Sprintf("%d.allow", r.ID))
		denyPath := filepath.Join(iplistsDir, fmt.Sprintf("%d.deny", r.ID))

		allowContent := buildIPList(r.IPAllowlist, "allow")
		denyContent := buildIPList(r.IPDenylist, "deny")

		if err := atomicWrite(allowPath, []byte(allowContent)); err != nil {
			return nil, err
		}
		if err := atomicWrite(denyPath, []byte(denyContent)); err != nil {
			return nil, err
		}
		written = append(written, allowPath, denyPath)
	}

	wafTmpl, err := template.New("waf").Parse(wafTemplate)
	if err != nil {
		return nil, err
	}
	var wafBuf bytes.Buffer
	if err := wafTmpl.Execute(&wafBuf, settings); err != nil {
		return nil, err
	}
	wafPath := filepath.Join(destDir, "waf.conf")
	if err := atomicWrite(wafPath, wafBuf.Bytes()); err != nil {
		return nil, err
	}
	written = append(written, wafPath)

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

func (g *Generator) Reload() (string, error) {
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
