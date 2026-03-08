package api

import (
	"encoding/json"
	"net/http"

	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
	"github.com/mehmettopcu/edgepanel/internal/validation"
)

type ApplyHandler struct {
	DB        *db.DB
	Generator *nginx.Generator
}

func (h *ApplyHandler) Apply(w http.ResponseWriter, r *http.Request) {
	routes, err := h.DB.ListRoutes()
	if err != nil {
		http.Error(w, "failed to get routes", http.StatusInternalServerError)
		return
	}
	settings, err := h.DB.GetGlobalSettings()
	if err != nil {
		http.Error(w, "failed to get settings", http.StatusInternalServerError)
		return
	}

	// Schema-validate every route before touching the filesystem.
	schemaMap, err := h.DB.GetConfigSchemaMap()
	if err != nil {
		http.Error(w, "failed to load config schema", http.StatusInternalServerError)
		return
	}
	for _, route := range routes {
		if errs := validation.ValidateRoute(route, schemaMap); errs.HasErrors() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":    "route validation failed before apply",
				"route_id": route.ID,
				"route":    route.Name,
				"fields":   errs,
			})
			return
		}
	}

	// Validate global settings paranoia level.
	if errs := validation.ValidateGlobalSettings(settings.WAFParanoiaLevel, schemaMap); errs.HasErrors() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  "global settings validation failed",
			"fields": errs,
		})
		return
	}

	// Generate configs into a staging directory, run nginx -t against the staging
	// tree, and only swap to the live directory when the test passes.
	testOut, err := h.Generator.GenerateAndTest(routes, settings)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "nginx config test failed",
			"output": testOut,
		})
		return
	}

	reloadOut, err := h.Generator.Reload()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "nginx reload failed",
			"output": reloadOut,
		})
		return
	}
	claims := auth.GetClaims(r)
	h.DB.CreateAuditLog(&claims.UserID, claims.Username, "apply_nginx", "system", nil, "nginx config applied and reloaded")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "nginx config applied and reloaded", "output": reloadOut})
}

