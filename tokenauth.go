package tokenauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/flohoss/tokenauth/pkg/cookie"
	"github.com/flohoss/tokenauth/pkg/ratelimiter"
	"github.com/flohoss/tokenauth/pkg/token"
)

type Config struct {
	TokenParam          string              `json:"tokenParam,omitempty"`
	AllowedTokens       []string            `json:"allowedTokens,omitempty"`
	MaxRateLimitEntries int                 `json:"maxRateLimitEntries,omitempty"`
	Cookie              cookie.CookieConfig `json:"cookie,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TokenParam:          "token",
		MaxRateLimitEntries: 10000,
		Cookie:              cookie.DefaultCookieConfig(),
	}
}

type tokenAuth struct {
	next          http.Handler
	name          string
	tokenParam    string
	allowedTokens []string
	rateLimiter   *ratelimiter.RateLimiter
	token         *token.Token
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
		rateLimiter:   ratelimiter.New(),
		token:         token.New(config.AllowedTokens),
		maxEntries:    config.MaxRateLimitEntries,
		cookie: &http.Cookie{
			Name:     config.Cookie.Name,
			Path:     "/",
			HttpOnly: config.Cookie.HttpOnly,
			Secure:   config.Cookie.Secure,
			MaxAge:   config.Cookie.MaxAge,
			SameSite: cookie.ParseSameSite(config.Cookie.SameSite),
		},
	}, nil
}

func (t *tokenAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := req.Header.Get("X-Real-IP")
	if t.rateLimiter != nil && t.rateLimiter.IsBlocked(clientIP) {
		http.Error(rw, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	cookie, err := req.Cookie(t.cookie.Name)
	if err == nil && t.token.Valid(cookie.Value, true) {
		t.next.ServeHTTP(rw, req)
		return
	}

	param := req.URL.Query().Get(t.tokenParam)
	if param == "" {
		if t.rateLimiter != nil {
			t.rateLimiter.RecordFailedAttempt(clientIP, t.maxEntries)
		}
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !t.token.Valid(param, false) {
		if t.rateLimiter != nil {
			t.rateLimiter.RecordFailedAttempt(clientIP, t.maxEntries)
		}
		http.Error(rw, "Invalid token", http.StatusUnauthorized)
		return
	}

	t.cookie.Value = token.HashToken(param)
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
