package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
	"github.com/mehmettopcu/edgepanel/internal/models"
)

type RoutesHandler struct {
	DB *db.DB
}

func (h *RoutesHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	var routes []*models.Route
	var err error
	if claims.IsAdmin {
		routes, err = h.DB.ListRoutes()
	} else {
		routes, err = h.DB.ListRoutesByUserID(claims.UserID)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if routes == nil {
		routes = []*models.Route{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

func (h *RoutesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var route models.Route
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if route.MaintenanceMode == "" {
		route.MaintenanceMode = "global"
	}
	if route.IPDefaultPolicy == "" {
		route.IPDefaultPolicy = "allow"
	}
	created, err := h.DB.CreateRoute(&route)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	claims := auth.GetClaims(r)
	rid := created.ID
	h.DB.CreateAuditLog(&claims.UserID, claims.Username, "create_route", "route", &rid, created.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func (h *RoutesHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	route, err := h.DB.GetRouteByID(id)
	if err != nil || route == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := auth.GetClaims(r)
	if !claims.IsAdmin {
		assignment, _ := h.DB.GetAssignment(claims.UserID, id)
		if assignment == nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (h *RoutesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	existing, err := h.DB.GetRouteByID(id)
	if err != nil || existing == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := auth.GetClaims(r)
	if !claims.IsAdmin {
		assignment, _ := h.DB.GetAssignment(claims.UserID, id)
		if assignment == nil || assignment.Role == "viewer" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	var updated models.Route
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	updated.ID = id
	if err := h.DB.UpdateRoute(&updated); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.DB.CreateAuditLog(&claims.UserID, claims.Username, "update_route", "route", &id, updated.Name)
	route, _ := h.DB.GetRouteByID(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (h *RoutesHandler) ToggleMaintenance(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	route, err := h.DB.GetRouteByID(id)
	if err != nil || route == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := auth.GetClaims(r)
	if !claims.IsAdmin {
		assignment, _ := h.DB.GetAssignment(claims.UserID, id)
		if assignment == nil || assignment.Role == "viewer" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	var req struct {
		Enabled         bool   `json:"enabled"`
		Mode            string `json:"mode"`
		Paths           string `json:"paths"`
		AllowlistBypass bool   `json:"allowlist_bypass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	route.MaintenanceEnabled = req.Enabled
	if req.Mode != "" {
		route.MaintenanceMode = req.Mode
	}
	route.MaintenancePaths = req.Paths
	route.AllowlistBypass = req.AllowlistBypass
	if err := h.DB.UpdateRoute(route); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	action := "disable_maintenance"
	if req.Enabled {
		action = "enable_maintenance"
	}
	h.DB.CreateAuditLog(&claims.UserID, claims.Username, action, "route", &id, route.Name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (h *RoutesHandler) SetIPFilter(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	route, err := h.DB.GetRouteByID(id)
	if err != nil || route == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	claims := auth.GetClaims(r)
	if !claims.IsAdmin {
		assignment, _ := h.DB.GetAssignment(claims.UserID, id)
		if assignment == nil || assignment.Role == "viewer" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	var req struct {
		Enabled       bool   `json:"enabled"`
		DefaultPolicy string `json:"default_policy"`
		Allowlist     string `json:"allowlist"`
		Denylist      string `json:"denylist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	route.IPFilterEnabled = req.Enabled
	if req.DefaultPolicy != "" {
		route.IPDefaultPolicy = req.DefaultPolicy
	}
	route.IPAllowlist = req.Allowlist
	route.IPDenylist = req.Denylist
	if err := h.DB.UpdateRoute(route); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.DB.CreateAuditLog(&claims.UserID, claims.Username, "update_ip_filter", "route", &id, route.Name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}
