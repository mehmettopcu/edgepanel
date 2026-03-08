package api

import (
	"encoding/json"
	"net/http"

	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/models"
	"github.com/mehmettopcu/edgepanel/internal/validation"
)

// SettingsHandler handles global WAF settings and exposes the config schema.
type SettingsHandler struct {
	DB *db.DB
}

// GetSettings returns the current global settings (GET /api/settings).
func (h *SettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	gs, err := h.DB.GetGlobalSettings()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gs)
}

// UpdateSettings updates global WAF settings with schema validation (PUT /api/settings).
func (h *SettingsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req models.GlobalSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	schemaMap, err := h.DB.GetConfigSchemaMap()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if errs := validation.ValidateGlobalSettings(req.WAFParanoiaLevel, schemaMap); errs.HasErrors() {
		writeValidationErrors(w, errs)
		return
	}

	current, err := h.DB.GetGlobalSettings()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	current.WAFEnabled = req.WAFEnabled
	current.WAFParanoiaLevel = req.WAFParanoiaLevel
	if err := h.DB.UpdateGlobalSettings(current); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	claims := auth.GetClaims(r)
	h.DB.CreateAuditLog(&claims.UserID, claims.Username, "update_global_settings", "system", nil,
		"global WAF settings updated")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(current)
}

// GetSchema returns the full config schema (GET /api/schema).
// This allows API clients and UIs to discover parameter constraints dynamically.
func (h *SettingsHandler) GetSchema(w http.ResponseWriter, r *http.Request) {
	schema, err := h.DB.ListConfigSchema()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if schema == nil {
		schema = []*models.NginxConfigSchema{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schema)
}
