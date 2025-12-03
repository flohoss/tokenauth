package token_auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHashToken(t *testing.T) {
	token := "secret-token"
	hash1 := hashToken(token)
	hash2 := hashToken(token)

	if hash1 != hash2 {
		t.Error("Same token should produce same hash")
	}

	if hash1 == token {
		t.Error("Hash should differ from plaintext token")
	}

	if len(hash1) != 64 {
		t.Errorf("SHA-256 hash should be 64 characters, got %d", len(hash1))
	}
}

func TestNew(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	t.Run("valid config", func(t *testing.T) {
		config := &Config{
			TokenParam:          "token",
			AllowedTokens:       []string{"secret"},
			MaxRateLimitEntries: 1000,
			Cookie: CookieConfig{
				Name: "session",
			},
		}

		handler, err := New(context.Background(), next, config, "test")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		if handler == nil {
			t.Fatal("Handler should not be nil")
		}
	})

	t.Run("empty allowed tokens", func(t *testing.T) {
		config := &Config{
			TokenParam: "token",
			Cookie:     CookieConfig{Name: "session"},
		}

		_, err := New(context.Background(), next, config, "test")
		if err == nil {
			t.Error("Expected error for empty allowed tokens")
		}
	})

	t.Run("empty token param", func(t *testing.T) {
		config := &Config{
			AllowedTokens: []string{"secret"},
			Cookie:        CookieConfig{Name: "session"},
		}

		_, err := New(context.Background(), next, config, "test")
		if err == nil {
			t.Error("Expected error for empty token param")
		}
	})

	t.Run("empty cookie name", func(t *testing.T) {
		config := &Config{
			TokenParam:    "token",
			AllowedTokens: []string{"secret"},
		}

		_, err := New(context.Background(), next, config, "test")
		if err == nil {
			t.Error("Expected error for empty cookie name")
		}
	})
}

func TestServeHTTP_ValidToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		TokenParam:          "token",
		AllowedTokens:       []string{"valid-token"},
		MaxRateLimitEntries: 1000,
		Cookie: CookieConfig{
			Name:     "auth_session",
			HttpOnly: true,
			Secure:   true,
			SameSite: "Strict",
		},
	}

	handler, _ := New(context.Background(), next, config, "test")

	req := httptest.NewRequest("GET", "http://example.com?token=valid-token", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("Expected status %d, got %d", http.StatusTemporaryRedirect, rr.Code)
	}

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected cookie to be set")
	}

	cookie := cookies[0]
	if cookie.Name != "auth_session" {
		t.Errorf("Expected cookie name 'auth_session', got '%s'", cookie.Name)
	}

	if !cookie.HttpOnly {
		t.Error("Cookie should be HttpOnly")
	}

	if !cookie.Secure {
		t.Error("Cookie should be Secure")
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("Cookie should have SameSite=Strict")
	}
}

func TestServeHTTP_InvalidToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	config := &Config{
		TokenParam:          "token",
		AllowedTokens:       []string{"valid-token"},
		MaxRateLimitEntries: 1000,
		Cookie:              CookieConfig{Name: "session"},
	}

	handler, _ := New(context.Background(), next, config, "test")

	req := httptest.NewRequest("GET", "http://example.com?token=invalid-token", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestServeHTTP_ValidCookie(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		TokenParam:          "token",
		AllowedTokens:       []string{"valid-token"},
		MaxRateLimitEntries: 1000,
		Cookie:              CookieConfig{Name: "session"},
	}

	handler, _ := New(context.Background(), next, config, "test")

	tokenHash := hashToken("valid-token")
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	req.AddCookie(&http.Cookie{Name: "session", Value: tokenHash})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("Next handler should have been called")
	}

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestServeHTTP_RateLimitBlocked(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called when rate limited")
	})

	config := &Config{
		TokenParam:          "token",
		AllowedTokens:       []string{"valid-token"},
		MaxRateLimitEntries: 1000,
		Cookie:              CookieConfig{Name: "session"},
	}

	handler, _ := New(context.Background(), next, config, "test")
	ta := handler.(*tokenAuth)

	for i := 0; i < 5; i++ {
		ta.rateLimiter.recordFailedAttempt("192.168.1.1", ta.maxEntries)
	}

	req := httptest.NewRequest("GET", "http://example.com?token=valid-token", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rr.Code)
	}
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config.TokenParam != "token" {
		t.Errorf("Expected TokenParam 'token', got '%s'", config.TokenParam)
	}

	if config.MaxRateLimitEntries != 10000 {
		t.Errorf("Expected MaxRateLimitEntries 10000, got %d", config.MaxRateLimitEntries)
	}

	if config.Cookie.Name != "auth_session" {
		t.Errorf("Expected Cookie.Name 'auth_session', got '%s'", config.Cookie.Name)
	}

	if !config.Cookie.HttpOnly {
		t.Error("Default cookie should be HttpOnly")
	}

	if !config.Cookie.Secure {
		t.Error("Default cookie should be Secure")
	}

	if config.Cookie.SameSite != "Strict" {
		t.Errorf("Expected SameSite 'Strict', got '%s'", config.Cookie.SameSite)
	}
}
