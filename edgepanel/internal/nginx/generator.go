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
{{if .WAFEnabled}}
    modsecurity on;
    modsecurity_rules_file /etc/modsecurity.d/owasp-crs/crs-setup.conf;
{{end}}
{{if .MaintenanceEnabled}}
{{if eq .MaintenanceMode "global"}}
    location / {
{{if .AllowlistBypass}}
        # Allowlisted IPs bypass maintenance; all others are denied with 503.
        include /etc/nginx/conf.d/generated/iplists/{{.ID}}.allow;
        deny all;
        error_page 403 /maintenance.html;
{{else}}
        return 503;
        error_page 503 /maintenance.html;
{{end}}
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
	ConfigDir   string
	NginxBinary string
}

func New(configDir, nginxBinary string) *Generator {
	return &Generator{
		ConfigDir:   configDir,
		NginxBinary: nginxBinary,
	}
}

func (g *Generator) Generate(routes []*models.Route, settings *models.GlobalSettings) error {
	routesDir := filepath.Join(g.ConfigDir, "routes")
	iplistsDir := filepath.Join(g.ConfigDir, "iplists")

	for _, dir := range []string{routesDir, iplistsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	tmpl, err := template.New("route").Parse(routeTemplate)
	if err != nil {
		return fmt.Errorf("parse route template: %w", err)
	}

	for _, r := range routes {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, r); err != nil {
			return fmt.Errorf("execute template for route %d: %w", r.ID, err)
		}
		confPath := filepath.Join(routesDir, fmt.Sprintf("%d.conf", r.ID))
		if err := atomicWrite(confPath, buf.Bytes()); err != nil {
			return fmt.Errorf("write route config %d: %w", r.ID, err)
		}

		allowPath := filepath.Join(iplistsDir, fmt.Sprintf("%d.allow", r.ID))
		denyPath := filepath.Join(iplistsDir, fmt.Sprintf("%d.deny", r.ID))

		allowContent := buildIPList(r.IPAllowlist, "allow")
		denyContent := buildIPList(r.IPDenylist, "deny")

		if err := atomicWrite(allowPath, []byte(allowContent)); err != nil {
			return err
		}
		if err := atomicWrite(denyPath, []byte(denyContent)); err != nil {
			return err
		}
	}

	wafTmpl, err := template.New("waf").Parse(wafTemplate)
	if err != nil {
		return err
	}
	var wafBuf bytes.Buffer
	if err := wafTmpl.Execute(&wafBuf, settings); err != nil {
		return err
	}
	wafPath := filepath.Join(g.ConfigDir, "waf.conf")
	if err := atomicWrite(wafPath, wafBuf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (g *Generator) Test() (string, error) {
	cmd := exec.Command(g.NginxBinary, "-t")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (g *Generator) Reload() (string, error) {
	cmd := exec.Command(g.NginxBinary, "-s", "reload")
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
