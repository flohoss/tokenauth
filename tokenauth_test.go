package tokenauth

import (
	"context"
	"net/http"
	"testing"

	"github.com/flohoss/tokenauth/pkg/cookie"
)

func TestEmptyAllowedTokens(t *testing.T) {
	config := &Config{
		TokenParam:    "token",
		AllowedTokens: []string{},
		Cookie:        cookie.DefaultCookieConfig(),
	}

	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err == nil {
		t.Error("expected error for empty allowedTokens, but got none")
	}
	if err.Error() != "allowedTokens cannot be empty" {
		t.Errorf("expected 'allowedTokens cannot be empty', got: %v", err)
	}
}

func TestEmptyTokenParam(t *testing.T) {
	config := &Config{
		TokenParam:    "",
		AllowedTokens: []string{"abcdefghijklmnopqrstuvwxyz012345"},
		Cookie:        cookie.DefaultCookieConfig(),
	}

	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err == nil {
		t.Error("expected error for empty tokenParam, but got none")
	}
	if err.Error() != "tokenParam cannot be empty" {
		t.Errorf("expected 'tokenParam cannot be empty', got: %v", err)
	}
}

func TestEmptyCookieName(t *testing.T) {
	cfg := cookie.DefaultCookieConfig()
	cfg.Name = ""

	config := &Config{
		TokenParam:    "token",
		AllowedTokens: []string{"abcdefghijklmnopqrstuvwxyz012345"},
		Cookie:        cfg,
	}

	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err == nil {
		t.Error("expected error for empty cookie.Name, but got none")
	}
	if err.Error() != "cookie.Name cannot be empty" {
		t.Errorf("expected 'cookie.Name cannot be empty', got: %v", err)
	}
}

func TestNegativeMaxAge(t *testing.T) {
	cfg := cookie.DefaultCookieConfig()
	cfg.MaxAge = -999

	config := &Config{
		TokenParam:    "token",
		AllowedTokens: []string{"abcdefghijklmnopqrstuvwxyz012345"},
		Cookie:        cfg,
	}

	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err == nil {
		t.Error("expected error for negative MaxAge, but got none")
	}
	if err.Error() != "cookie.MaxAge cannot be negative" {
		t.Errorf("expected 'cookie.MaxAge cannot be negative', got: %v", err)
	}
}

func TestInvalidTokenLength(t *testing.T) {
	config := &Config{
		TokenParam:    "token",
		AllowedTokens: []string{"short"},
		Cookie:        cookie.DefaultCookieConfig(),
	}

	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err == nil {
		t.Error("expected error for invalid token length, but got none")
	}
}

func TestInvalidErrorRedirectURL(t *testing.T) {
	tests := []struct {
		name             string
		errorRedirectURL string
		expectError      bool
	}{
		{
			name:             "valid absolute URL with https",
			errorRedirectURL: "https://example.com/error",
			expectError:      false,
		},
		{
			name:             "valid absolute URL with http",
			errorRedirectURL: "http://localhost:8080/error",
			expectError:      false,
		},
		{
			name:             "empty string is valid",
			errorRedirectURL: "",
			expectError:      false,
		},
		{
			name:             "relative URL is invalid",
			errorRedirectURL: "/error",
			expectError:      true,
		},
		{
			name:             "invalid URL with bad characters",
			errorRedirectURL: "ht\ttp://invalid",
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				TokenParam:       "token",
				AllowedTokens:    []string{"abcdefghijklmnopqrstuvwxyz012345"},
				Cookie:           cookie.DefaultCookieConfig(),
				ErrorRedirectURL: tt.errorRedirectURL,
			}

			_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

			if tt.expectError && err == nil {
				t.Errorf("expected error for invalid URL, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, but got: %v", err)
			}
		})
	}
}

func TestValidConfig(t *testing.T) {
	config := &Config{
		TokenParam:       "token",
		AllowedTokens:    []string{"abcdefghijklmnopqrstuvwxyz012345"},
		Cookie:           cookie.DefaultCookieConfig(),
		ErrorRedirectURL: "https://example.com/error",
	}

	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err != nil {
		t.Errorf("expected no error for valid config, but got: %v", err)
	}
	if handler == nil {
		t.Error("expected handler to be created, but got nil")
	}
}

func TestMultipleValidTokens(t *testing.T) {
	config := &Config{
		TokenParam: "token",
		AllowedTokens: []string{
			"abcdefghijklmnopqrstuvwxyz012345",
			"zyxwvutsrqponmlkjihgfedcba543210",
			"1234567890abcdefghijklmnopqrstuv",
		},
		Cookie: cookie.DefaultCookieConfig(),
	}

	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err != nil {
		t.Errorf("expected no error with multiple tokens, but got: %v", err)
	}
	if handler == nil {
		t.Error("expected handler to be created, but got nil")
	}
}

func TestMultipleTokensWithOneInvalid(t *testing.T) {
	config := &Config{
		TokenParam: "token",
		AllowedTokens: []string{
			"abcdefghijklmnopqrstuvwxyz012345",
			"short",
			"zyxwvutsrqponmlkjihgfedcba543210",
		},
		Cookie: cookie.DefaultCookieConfig(),
	}

	_, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}), config, "test")

	if err == nil {
		t.Error("expected error when one token is invalid, but got none")
	}
}
