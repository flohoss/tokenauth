package token_auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
)

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

type Config struct {
	TokenParam          string       `json:"tokenParam,omitempty"`
	AllowedTokens       []string     `json:"allowedTokens,omitempty"`
	MaxRateLimitEntries int          `json:"maxRateLimitEntries,omitempty"`
	Cookie              CookieConfig `json:"cookie,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TokenParam:          "token",
		MaxRateLimitEntries: 10000,
		Cookie:              defaultCookieConfig(),
	}
}

type tokenAuth struct {
	next          http.Handler
	name          string
	tokenParam    string
	allowedTokens []string
	rateLimiter   *AuthRateLimiter
	maxEntries    int
	cookie        *http.Cookie
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.AllowedTokens) == 0 {
		return nil, fmt.Errorf("allowedTokens cannot be empty")
	}

	if len(config.TokenParam) == 0 {
		return nil, fmt.Errorf("tokenParam cannot be empty")
	}

	if len(config.Cookie.Name) == 0 {
		return nil, fmt.Errorf("cookie.Name cannot be empty")
	}

	if config.MaxRateLimitEntries <= 0 {
		return nil, fmt.Errorf("maxRateLimitEntries must be greater than zero")
	}

	if config.Cookie.MaxAge < 0 {
		return nil, fmt.Errorf("cookie.MaxAge cannot be negative")
	}

	return &tokenAuth{
		next:          next,
		name:          name,
		tokenParam:    config.TokenParam,
		allowedTokens: config.AllowedTokens,
		rateLimiter:   NewAuthRateLimiter(),
		maxEntries:    config.MaxRateLimitEntries,
		cookie: &http.Cookie{
			Name:     config.Cookie.Name,
			Path:     "/",
			HttpOnly: config.Cookie.HttpOnly,
			Secure:   config.Cookie.Secure,
			MaxAge:   config.Cookie.MaxAge,
			SameSite: parseSameSite(config.Cookie.SameSite),
		},
	}, nil
}

func (t *tokenAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := req.Header.Get("X-Real-IP")
	if t.rateLimiter != nil && t.rateLimiter.isBlocked(clientIP) {
		http.Error(rw, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	cookie, err := req.Cookie(t.cookie.Name)
	if err == nil && t.isTokenValid(cookie.Value, true) {
		t.next.ServeHTTP(rw, req)
		return
	}

	token := req.URL.Query().Get(t.tokenParam)
	if token == "" {
		if t.rateLimiter != nil {
			t.rateLimiter.recordFailedAttempt(clientIP, t.maxEntries)
		}
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !t.isTokenValid(token, false) {
		if t.rateLimiter != nil {
			t.rateLimiter.recordFailedAttempt(clientIP, t.maxEntries)
		}
		http.Error(rw, "Invalid token", http.StatusUnauthorized)
		return
	}

	t.cookie.Value = hashToken(token)
	http.SetCookie(rw, t.cookie)

	q := req.URL.Query()
	q.Del(t.tokenParam)
	req.URL.RawQuery = q.Encode()

	newURL := &url.URL{
		Scheme:   req.URL.Scheme,
		Host:     req.URL.Host,
		Path:     req.URL.Path,
		RawQuery: q.Encode(),
	}

	http.Redirect(rw, req, newURL.String(), http.StatusTemporaryRedirect)
}

func (t *tokenAuth) isTokenValid(token string, isHash bool) bool {
	if len(t.allowedTokens) == 0 {
		return false
	}

	providedHash := token
	if !isHash {
		providedHash = hashToken(token)
	}

	for _, allowedToken := range t.allowedTokens {
		allowedHash := hashToken(allowedToken)
		if providedHash == allowedHash {
			return true
		}
	}
	return false
}
