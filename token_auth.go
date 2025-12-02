package token_auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	TokenKey            = "token"
	CookieKey           = "auth_session"
	maxRateLimitEntries = 10000
)

type AuthRateLimiter struct {
	attempts   map[string]int
	lastTry    map[string]time.Time
	lastAccess map[string]time.Time
	mu         sync.RWMutex
}

func NewAuthRateLimiter() *AuthRateLimiter {
	return &AuthRateLimiter{
		attempts:   make(map[string]int),
		lastTry:    make(map[string]time.Time),
		lastAccess: make(map[string]time.Time),
	}
}

func (rl *AuthRateLimiter) isBlocked(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	attempts, exists := rl.attempts[ip]
	if !exists {
		return false
	}

	rl.lastAccess[ip] = time.Now()

	if rl.shouldResetAttemptsForIP(ip) {
		rl.resetAttemptsForIP(ip)
		return false
	}

	return attempts >= 5
}

func (rl *AuthRateLimiter) shouldResetAttemptsForIP(ip string) bool {
	lastTry, exists := rl.lastTry[ip]
	return exists && time.Since(lastTry) > time.Hour
}

func (rl *AuthRateLimiter) resetAttemptsForIP(ip string) {
	delete(rl.attempts, ip)
	delete(rl.lastTry, ip)
	delete(rl.lastAccess, ip)
}

func (rl *AuthRateLimiter) recordFailedAttempt(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.attempts) >= maxRateLimitEntries {
		if _, exists := rl.attempts[ip]; !exists {
			rl.evictOldestEntry()
		}
	}

	now := time.Now()
	rl.attempts[ip]++
	rl.lastTry[ip] = now
	rl.lastAccess[ip] = now
}

func (rl *AuthRateLimiter) evictOldestEntry() {
	if len(rl.lastAccess) == 0 {
		return
	}

	var oldestIP string
	var oldestTime time.Time
	first := true

	for ip, accessTime := range rl.lastAccess {
		if first || accessTime.Before(oldestTime) {
			oldestIP = ip
			oldestTime = accessTime
			first = false
		}
	}

	if oldestIP != "" {
		delete(rl.attempts, oldestIP)
		delete(rl.lastTry, oldestIP)
		delete(rl.lastAccess, oldestIP)
	}
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

type Config struct {
	TokenParam    string   `json:"token_param,omitempty"`
	CookieName    string   `json:"cookie_name,omitempty"`
	AllowedTokens []string `json:"allowed_tokens,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TokenParam: TokenKey,
		CookieName: CookieKey,
	}
}

type tokenAuth struct {
	next          http.Handler
	name          string
	tokenParam    string
	cookieName    string
	allowedTokens []string
	rateLimiter   *AuthRateLimiter
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.TokenParam) == 0 {
		config.TokenParam = TokenKey
	}
	if len(config.CookieName) == 0 {
		config.CookieName = CookieKey
	}

	return &tokenAuth{
		next:          next,
		name:          name,
		tokenParam:    config.TokenParam,
		cookieName:    config.CookieName,
		allowedTokens: config.AllowedTokens,
		rateLimiter:   NewAuthRateLimiter(),
	}, nil
}

func (t *tokenAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := req.Header.Get("X-Real-IP")
	if t.rateLimiter != nil && t.rateLimiter.isBlocked(clientIP) {
		http.Error(rw, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	cookie, err := req.Cookie(t.cookieName)
	if err == nil && t.isTokenValid(cookie.Value, true) {
		t.next.ServeHTTP(rw, req)
		return
	}

	token := req.URL.Query().Get(t.tokenParam)
	if token == "" {
		if t.rateLimiter != nil {
			t.rateLimiter.recordFailedAttempt(clientIP)
		}
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !t.isTokenValid(token, false) {
		if t.rateLimiter != nil {
			t.rateLimiter.recordFailedAttempt(clientIP)
		}
		http.Error(rw, "Invalid token", http.StatusUnauthorized)
		return
	}

	tokenHash := hashToken(token)
	cookie = &http.Cookie{
		Name:     t.cookieName,
		Value:    tokenHash,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(rw, cookie)

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
