# EdgePanel

**OSS Edge Gateway Control Panel** — a lightweight web UI for managing an NGINX reverse-proxy fleet with per-route WAF (ModSecurity + OWASP CRS 4.x), maintenance mode, IP filtering, Prometheus metrics, and Grafana dashboards.

---

## Architecture

EdgePanel uses a **server-agent** pattern to decouple the control plane from the nginx data plane:

```
                  ┌────────────────────────────────────────────────────────┐
Internet ──80──▶  │  nginx-edge container                                  │
                  │  ┌───────────────────────────────────────────────────┐ │
                  │  │  NGINX + ModSecurity CRS 4  (port 80 / 8080)     │ │
                  │  └───────────────────────────────────────────────────┘ │
                  │  ┌───────────────────────────────────────────────────┐ │
                  │  │  nginx-agent  (port 9090, internal only)          │ │
                  │  │  POST /apply  ──writes configs──▶ nginx -t/-s reload│
                  │  └──────────────────────▲────────────────────────────┘ │
                  └─────────────────────────│──────────────────────────────┘
                                            │ HTTP (internal network only)
                  ┌─────────────────────────┴────────────────────────────┐
                  │  edgepanel  (Go control-plane, port 8081)            │
                  │  Generates configs in memory → POST to nginx-agent   │
                  └──────────────────────────────────────────────────────┘
                  ┌──────────────┐  ┌───────────────────────┐
                  │  backend1    │  │  backend2              │
                  │  (nginx:alp) │  │  (nginx:alp)           │
                  └──────────────┘  └───────────────────────┘
                  ┌────────────────────────────────────────────────────────┐
                  │  Prometheus (9090)  +  Grafana (3000)                  │
                  └────────────────────────────────────────────────────────┘
```

### How config updates flow

1. An operator saves a route change or clicks **Apply** in edgepanel.
2. edgepanel renders all nginx config files **in memory** (Go templates → `map[string]string`).
3. edgepanel sends the complete file map to `nginx-agent` via `POST http://nginx-edge:9090/apply`.
4. nginx-agent writes each file atomically (write to `.tmp`, then rename), runs `nginx -t` to validate, and on success calls `nginx -s reload`.
5. If `nginx -t` fails, the live config is **never touched** — edgepanel receives a `400` error with the nginx output.

This approach removes the need for a shared Docker volume between edgepanel and nginx, and eliminates the Docker socket (`docker.sock`) mount that the old architecture required.

| Service | Image / Build | Port | Notes |
|---|---|---|---|
| `nginx-edge` | local multi-stage build | 80 (HTTP), 8080 (stub_status) | Contains NGINX + ModSecurity CRS 4 + nginx-agent sidecar |
| `nginx-agent` | embedded in `nginx-edge` | 9090 (internal only) | Receives config from edgepanel, writes files, tests & reloads nginx |
| `edgepanel` | local Go build | 8081 → 8080 (internal) | Control plane; generates configs in memory and POSTs to nginx-agent |
| `backend1/2` | `nginx:alpine` | internal only | Demo backends |
| `prometheus` | `prom/prometheus:v2.51.0` | 9090 | Metrics |
| `nginx-exporter` | `nginx/nginx-prometheus-exporter:1.1.0` | 9113 | Scrapes nginx stub_status |
| `grafana` | `grafana/grafana:10.4.2` | 3000 | Dashboards |

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/mehmettopcu/edgepanel.git
cd edgepanel

# 2. Configure secrets
cp .env.example .env
# Edit .env — set JWT_SECRET, NGINX_AGENT_TOKEN, and GRAFANA_ADMIN_PASSWORD

# 3. Start the stack
docker compose up -d --build

# 4. Open the control panel
open http://localhost:8081
```

### Default credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `admin` | admin |

**Change the password immediately after first login.**

---

## Adding a Subdomain Route

1. Log in as an admin at `http://localhost:8081`.
2. Navigate to **Routes → New Route**.
3. Fill in:
   - **Subdomain** — e.g. `app1.example.com`
   - **Upstream** — e.g. `http://backend1:80`
   - Optional: enable WAF, set paranoia level, enable IP filtering.
4. Click **Save**, then click **Apply** to generate the NGINX config and push it to the nginx-agent for a live reload.

Config files are written by nginx-agent to `/etc/nginx/conf.d/generated/routes/<id>.conf` inside the `nginx-edge` container. The nginx process picks them up on reload without restarting.

---

## Maintenance Mode

Each route can be put into maintenance mode independently.

- **Global** — every request to the subdomain returns `503` (or redirects to a custom `maintenance.html`).
- **Allowlist bypass** — requests from IPs in the route's allowlist pass through normally; all others receive `503`.
- **Path-specific** — only listed URL paths are blocked; the rest proxy as normal.

Toggle maintenance per-route from the route detail page, then click **Apply**.

---

## IP Filtering

Each route supports an independent IP filter with:

- **Allowlist** — CIDR ranges or single IPs that are always permitted.
- **Denylist** — CIDR ranges or single IPs that are always blocked.
- **Default policy** — `allow` (permissive) or `deny` (allowlist-only).

IP lists are rendered as NGINX `allow`/`deny` directives in `/etc/nginx/conf.d/generated/iplists/<id>.allow` and `<id>.deny` inside the `nginx-edge` container.

---

## WAF (ModSecurity + OWASP CRS)

The `nginx-edge` container is built on `owasp/modsecurity-crs:4-nginx-alpine`. ModSecurity is controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `MODSEC_RULE_ENGINE` | `On` | `On` / `DetectionOnly` / `Off` |
| `PARANOIA` | `1` | OWASP CRS paranoia level (1–4) |
| `ANOMALY_INBOUND` | `5` | Inbound anomaly score threshold |
| `ANOMALY_OUTBOUND` | `4` | Outbound anomaly score threshold |

Per-route WAF can be enabled/disabled from the control panel. When enabled, `modsecurity on;` is injected into the route's server block.

### Testing the WAF

```bash
# Should be blocked (SQL injection attempt)
curl -i "http://localhost/?id=1'+OR+'1'='1"

# Should be blocked (XSS attempt)
curl -i "http://localhost/?q=<script>alert(1)</script>"
```

When `MODSEC_RULE_ENGINE=DetectionOnly` the requests are logged but not blocked — useful for tuning.

---

## RBAC Model

| Role | Capabilities |
|---|---|
| `admin` | Full access: create/delete routes, manage users, apply config |
| `operator` | Edit assigned routes, toggle maintenance/IP filter, apply config |
| `viewer` | Read-only access to assigned routes (no edits, no apply) |

Users are assigned to specific routes. An operator can only modify routes they are assigned to. Admins see and manage everything.

All actions are written to the **Audit Log** (`/audit`), including who changed what and when.

---

## Metrics & Dashboards

- **Prometheus** scrapes `nginx-exporter` (NGINX stub_status) and the edgepanel `/metrics` endpoint every 15 s.
- **Grafana** is pre-provisioned with a *NGINX Edge Gateway* dashboard showing:
  - Active / reading / writing / waiting connections
  - Request rate (req/s)
  - Accepted vs handled connections
  - HTTP status code breakdown

Access Grafana at `http://localhost:3000` (default: `admin` / value of `GRAFANA_ADMIN_PASSWORD`).

---

## Environment Variables

### edgepanel

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | `changeme-please-use-env` | HMAC secret for JWT signing — **must be changed** |
| `DB_PATH` | `/data/edgepanel.db` | SQLite database path |
| `NGINX_AGENT_URL` | _(empty)_ | URL of the nginx-agent inside `nginx-edge` (e.g. `http://nginx-edge:9090`). When set, all config apply/reload operations are delegated to the agent. |
| `NGINX_AGENT_TOKEN` | _(empty)_ | Shared secret sent as `Authorization: Bearer <token>` to the nginx-agent. Must match `AGENT_TOKEN` in the `nginx-edge` container. |
| `PORT` | `8080` | edgepanel HTTP listen port |
| `GRAFANA_URL` | `http://localhost:3000` | URL shown on the Metrics page |
| `GRAFANA_ADMIN_PASSWORD` | `admin` | Grafana admin password |

### nginx-agent (inside nginx-edge)

| Variable | Default | Description |
|---|---|---|
| `AGENT_PORT` | `9090` | Port the nginx-agent HTTP server listens on |
| `AGENT_TOKEN` | _(empty)_ | Shared secret; when set, requests without a matching `Authorization: Bearer <token>` header are rejected with `401` |
| `CONFIG_DIR` | `/etc/nginx/conf.d/generated` | Directory where nginx-agent writes the rendered config files |
| `NGINX_BINARY` | `/usr/sbin/nginx` | Path to the nginx binary used for `-t` and `-s reload` |

---

## Security Notes

- **Change `JWT_SECRET`** before deploying. A weak secret allows token forgery.
- **Change `NGINX_AGENT_TOKEN`** before deploying. This shared secret is the only authentication layer between edgepanel and nginx-agent; leave it empty only in fully isolated environments.
- **Change the default `admin` password** immediately after first login.
- **Port 8080** (nginx stub_status) should not be exposed to the public internet. In production, remove the `8080:8080` port mapping and keep it on the internal Docker network only.
- **Port 9090** (nginx-agent) is deliberately **not** published to the host. It is reachable only within the internal `edge-net` Docker network. Do not publish it.
- **Port 8081** (edgepanel) should be placed behind a firewall or VPN in production.
- No Docker socket (`docker.sock`) is required. edgepanel and nginx-edge communicate only via HTTP over the internal Docker network, which eliminates the host-level privilege escalation risk that the old shared-socket approach carried.
- SQLite is stored in a named volume. Back up `/data/edgepanel.db` regularly.
- The WAF is set to `PARANOIA=1` by default. Increase to `2`–`4` for stricter enforcement, but expect more false positives — tune with `DetectionOnly` first.

---

## License

[MIT](LICENSE)
