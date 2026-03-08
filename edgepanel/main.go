package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mehmettopcu/edgepanel/internal/api"
	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
)

//go:embed web/templates/*.html
var templateFS embed.FS

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	port := getEnv("PORT", "8080")
	dbPath := getEnv("DB_PATH", "/data/edgepanel.db")
	nginxConfigDir := getEnv("NGINX_CONFIG_DIR", "/etc/nginx/conf.d/generated")
	nginxBinary := getEnv("NGINX_BINARY", "/usr/sbin/nginx")

	database, err := db.New(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	if err := database.SeedInitialData(); err != nil {
		log.Fatalf("failed to seed initial data: %v", err)
	}

	gen := nginx.New(nginxConfigDir, nginxBinary)

	tmpl := template.Must(template.ParseFS(templateFS, "web/templates/*.html"))

	authHandler := &api.AuthHandler{DB: database}
	routesHandler := &api.RoutesHandler{DB: database}
	usersHandler := &api.UsersHandler{DB: database}
	applyHandler := &api.ApplyHandler{DB: database, Generator: gen}
	auditHandler := &api.AuditHandler{DB: database}
	settingsHandler := &api.SettingsHandler{DB: database}
	uiHandler := &api.UIHandler{DB: database, Tmpl: tmpl}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Web UI routes
	r.Get("/", uiHandler.Index)
	r.Get("/login", uiHandler.LoginPage)
	r.Get("/routes", uiHandler.RoutesPage)
	r.Get("/routes/{id}", uiHandler.RouteDetailPage)
	r.Get("/users", uiHandler.UsersPage)
	r.Get("/audit", uiHandler.AuditPage)
	r.Get("/metrics", uiHandler.MetricsPage)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/logout", authHandler.Logout)

		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware)
			r.Get("/me", authHandler.Me)

			r.Get("/routes", routesHandler.List)
			r.Get("/routes/{id}", routesHandler.Get)
			r.Put("/routes/{id}", routesHandler.Update)
			r.Post("/routes/{id}/maintenance", routesHandler.ToggleMaintenance)
			r.Post("/routes/{id}/ip-filter", routesHandler.SetIPFilter)

			r.Post("/apply", applyHandler.Apply)
			r.Get("/audit", auditHandler.List)

			// Config schema — readable by all authenticated users
			r.Get("/schema", settingsHandler.GetSchema)

			// Global settings — readable by all, writable by admin only
			r.Get("/settings", settingsHandler.GetSettings)
			r.With(auth.AdminOnly).Put("/settings", settingsHandler.UpdateSettings)

			// Admin only
			r.Group(func(r chi.Router) {
				r.Use(auth.AdminOnly)
				r.Post("/routes", routesHandler.Create)
				r.Get("/users", usersHandler.List)
				r.Post("/users", usersHandler.Create)
				r.Put("/users/{id}", usersHandler.Update)
				r.Post("/users/{id}/assignments", usersHandler.Assign)
			})
		})
	})

	log.Printf("Starting edgepanel on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
