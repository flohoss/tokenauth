package token_auth

import (
	"net/http"
	"testing"
)

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input    string
		expected http.SameSite
	}{
		{"Strict", http.SameSiteStrictMode},
		{"Lax", http.SameSiteLaxMode},
		{"None", http.SameSiteNoneMode},
		{"", http.SameSiteDefaultMode},
		{"invalid", http.SameSiteDefaultMode},
	}

	for _, tt := range tests {
		result := parseSameSite(tt.input)
		if result != tt.expected {
			t.Errorf("parseSameSite(%q) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestDefaultCookieConfig(t *testing.T) {
	config := defaultCookieConfig()

	if config.Name != "auth_session" {
		t.Errorf("Expected Name 'auth_session', got '%s'", config.Name)
	}

	if !config.HttpOnly {
		t.Error("Default should be HttpOnly")
	}

	if !config.Secure {
		t.Error("Default should be Secure")
	}

	if config.SameSite != "Strict" {
		t.Errorf("Expected SameSite 'Strict', got '%s'", config.SameSite)
	}

	if config.MaxAge != 0 {
		t.Errorf("Expected MaxAge 0, got %d", config.MaxAge)
	}
}
