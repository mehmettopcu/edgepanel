package api

import (
	"html/template"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/mehmettopcu/edgepanel/internal/auth"
	"github.com/mehmettopcu/edgepanel/internal/db"
)

type UIHandler struct {
	DB        *db.DB
	Templates map[string]*template.Template
}

func (h *UIHandler) getAuthInfo(r *http.Request) (int64, string, bool, bool) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return 0, "", false, false
	}
	claims, err := auth.ParseToken(cookie.Value)
	if err != nil {
		return 0, "", false, false
	}
	return claims.UserID, claims.Username, claims.IsAdmin, true
}

func (h *UIHandler) Index(w http.ResponseWriter, r *http.Request) {
	_, _, _, loggedIn := h.getAuthInfo(r)
	if loggedIn {
		http.Redirect(w, r, "/routes", http.StatusFound)
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func (h *UIHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	h.Templates["login.html"].ExecuteTemplate(w, "login.html", nil)
}

func (h *UIHandler) RoutesPage(w http.ResponseWriter, r *http.Request) {
	userID, username, isAdmin, loggedIn := h.getAuthInfo(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	var routes interface{}
	var err error
	if isAdmin {
		routes, err = h.DB.ListRoutes()
	} else {
		routes, err = h.DB.ListRoutesByUserID(userID)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.Templates["routes.html"].ExecuteTemplate(w, "routes.html", map[string]interface{}{
		"Routes":   routes,
		"Username": username,
		"IsAdmin":  isAdmin,
	})
}

func (h *UIHandler) RouteDetailPage(w http.ResponseWriter, r *http.Request) {
	userID, username, isAdmin, loggedIn := h.getAuthInfo(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
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
	if !isAdmin {
		assignment, _ := h.DB.GetAssignment(userID, id)
		if assignment == nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	h.Templates["route_detail.html"].ExecuteTemplate(w, "route_detail.html", map[string]interface{}{
		"Route":    route,
		"Username": username,
		"IsAdmin":  isAdmin,
	})
}

func (h *UIHandler) UsersPage(w http.ResponseWriter, r *http.Request) {
	_, username, isAdmin, loggedIn := h.getAuthInfo(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !isAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	users, err := h.DB.ListUsers()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	routes, err := h.DB.ListRoutes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.Templates["users.html"].ExecuteTemplate(w, "users.html", map[string]interface{}{
		"Users":    users,
		"Routes":   routes,
		"Username": username,
		"IsAdmin":  isAdmin,
	})
}

func (h *UIHandler) AuditPage(w http.ResponseWriter, r *http.Request) {
	_, username, isAdmin, loggedIn := h.getAuthInfo(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	logs, err := h.DB.ListAuditLogs(200)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.Templates["audit.html"].ExecuteTemplate(w, "audit.html", map[string]interface{}{
		"Logs":     logs,
		"Username": username,
		"IsAdmin":  isAdmin,
	})
}

func (h *UIHandler) MetricsPage(w http.ResponseWriter, r *http.Request) {
	_, username, isAdmin, loggedIn := h.getAuthInfo(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	h.Templates["metrics.html"].ExecuteTemplate(w, "metrics.html", map[string]interface{}{
		"Username": username,
		"IsAdmin":  isAdmin,
	})
}
