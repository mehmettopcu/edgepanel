package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mehmettopcu/edgepanel/internal/auth"
)

// ---------------------------------------------------------------------------
// Password helpers
// ---------------------------------------------------------------------------

func TestHashAndCheckPassword(t *testing.T) {
	password := "supersecret"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if !auth.CheckPassword(hash, password) {
		t.Error("CheckPassword should return true for correct password")
	}
	if auth.CheckPassword(hash, "wrongpassword") {
		t.Error("CheckPassword should return false for wrong password")
	}
}

func TestHashPassword_UniqueHashes(t *testing.T) {
	h1, _ := auth.HashPassword("pass")
	h2, _ := auth.HashPassword("pass")
	if h1 == h2 {
		t.Error("bcrypt should produce different salts each time")
	}
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

func TestGenerateAndParseToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret-key-1234")

	token, err := auth.GenerateToken(42, "alice", true)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := auth.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken error: %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("expected UserID 42, got %d", claims.UserID)
	}
	if claims.Username != "alice" {
		t.Errorf("expected Username 'alice', got %q", claims.Username)
	}
	if !claims.IsAdmin {
		t.Error("expected IsAdmin true")
	}
}

func TestParseToken_Invalid(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret-key-1234")

	_, err := auth.ParseToken("this.is.not.a.valid.jwt")
	if err == nil {
		t.Error("expected error for invalid token string")
	}
}

func TestParseToken_WrongSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "secret-a")
	token, err := auth.GenerateToken(1, "bob", false)
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	t.Setenv("JWT_SECRET", "secret-b")
	_, err = auth.ParseToken(token)
	if err == nil {
		t.Error("expected error when parsing token with wrong secret")
	}
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func TestMiddleware_NoCookie_NoHeader(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if called {
		t.Error("next handler should not have been called")
	}
}

func TestMiddleware_ValidCookieToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	token, _ := auth.GenerateToken(7, "carol", false)

	var gotClaims *auth.Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = auth.GetClaims(r)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rr := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if gotClaims == nil {
		t.Fatal("expected claims in context")
	}
	if gotClaims.UserID != 7 {
		t.Errorf("expected UserID 7, got %d", gotClaims.UserID)
	}
}

func TestMiddleware_ValidBearerToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	token, _ := auth.GenerateToken(8, "dave", true)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "bad.token.value"})
	rr := httptest.NewRecorder()
	auth.Middleware(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// AdminOnly middleware
// ---------------------------------------------------------------------------

func TestAdminOnly_AdminUser(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	token, _ := auth.GenerateToken(1, "admin", true)

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rr := httptest.NewRecorder()

	// Chain Middleware → AdminOnly → next
	auth.Middleware(auth.AdminOnly(next)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !reached {
		t.Error("next handler should have been called for admin")
	}
}

func TestAdminOnly_NonAdminUser(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	token, _ := auth.GenerateToken(2, "viewer", false)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rr := httptest.NewRecorder()

	auth.Middleware(auth.AdminOnly(next)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// GetClaims
// ---------------------------------------------------------------------------

func TestGetClaims_NilWhenMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if c := auth.GetClaims(req); c != nil {
		t.Errorf("expected nil claims, got %v", c)
	}
}

func TestGetClaims_ReturnsClaimsFromContext(t *testing.T) {
	claims := &auth.Claims{UserID: 99, Username: "eve", IsAdmin: false}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.ClaimsKey, claims))
	got := auth.GetClaims(req)
	if got == nil || got.UserID != 99 {
		t.Errorf("expected UserID 99, got %v", got)
	}
}
