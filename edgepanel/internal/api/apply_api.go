package api

import (
	"encoding/json"
	"net/http"

	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/nginx"
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
	if err := h.Generator.Generate(routes, settings); err != nil {
		http.Error(w, "failed to generate config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	testOut, err := h.Generator.Test()
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
