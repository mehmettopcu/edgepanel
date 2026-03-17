# Stage 1: build nginx-agent
FROM golang:1.22-alpine AS agent-builder

WORKDIR /build
COPY nginx-agent/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o nginx-agent .

# Stage 2: nginx with embedded nginx-agent sidecar
FROM owasp/modsecurity-crs:4-nginx-alpine-202603150103

# Copy the compiled nginx-agent binary
COPY --from=agent-builder /build/nginx-agent /usr/local/bin/nginx-agent

# Create generated config directory structure
RUN mkdir -p /etc/nginx/conf.d/generated/routes \
             /etc/nginx/conf.d/generated/iplists

# Copy NGINX main config and remove the base image's template so the
# entrypoint doesn't try (and fail) to overwrite our file at startup.
USER root
COPY nginx/nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/templates/nginx.conf.template

# Maintenance page served when a route is in maintenance mode
COPY nginx/maintenance.html /usr/share/nginx/html/maintenance.html

# Startup script: launches nginx-agent in background then nginx in foreground
COPY nginx/start.sh /start.sh
RUN chmod +x /start.sh

# ModSecurity is enabled via MODSEC_RULE_ENGINE env var
# nginx-agent listens on port 9090 by default (AGENT_PORT env var)

EXPOSE 80 443 9090

CMD ["/start.sh"]
