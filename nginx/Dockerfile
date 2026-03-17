FROM owasp/modsecurity-crs:4-nginx-alpine-202405020410

# Create generated config directory structure
RUN mkdir -p /etc/nginx/conf.d/generated/routes \
             /etc/nginx/conf.d/generated/iplists

# Copy NGINX main config
COPY nginx.conf /etc/nginx/nginx.conf

# Maintenance page served when a route is in maintenance mode
COPY maintenance.html /usr/share/nginx/html/maintenance.html

# ModSecurity is enabled via MODSEC_RULE_ENGINE env var

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
