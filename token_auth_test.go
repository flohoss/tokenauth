package token_auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHashToken(t *testing.T) {
	token := "test-token-123"
	hash1 := hashToken(token)
	hash2 := hashToken(token)

	if hash1 != hash2 {
		t.Error("Same token should produce same hash")
	}

	if hash1 == token {
		t.Error("Hash should not equal plaintext token")
	}

	if len(hash1) != 64 {
		t.Errorf("SHA-256 hash should be 64 characters, got %d", len(hash1))
	}
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config.TokenParam != TokenKey {
		t.Errorf("Expected TokenParam %s, got %s", TokenKey, config.TokenParam)
	}

	if config.CookieName != CookieKey {
		t.Errorf("Expected CookieName %s, got %s", CookieKey, config.CookieName)
	}
}

func TestNew(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"test-token"},
	}

	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	if handler == nil {
		t.Fatal("Handler should not be nil")
	}
}

func TestNewWithDefaults(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		AllowedTokens: []string{"test-token"},
	}

	handler, err := New(context.Background(), nextHandler, config, "test")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	ta := handler.(*tokenAuth)
	if ta.tokenParam != TokenKey {
		t.Errorf("Expected default tokenParam %s, got %s", TokenKey, ta.tokenParam)
	}

	if ta.cookieName != CookieKey {
		t.Errorf("Expected default cookieName %s, got %s", CookieKey, ta.cookieName)
	}
}

func TestServeHTTP_ValidToken(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")

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

	if cookie.HttpOnly != true {
		t.Error("Cookie should be HttpOnly")
	}

	if cookie.Secure != true {
		t.Error("Cookie should be Secure")
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("Cookie should have SameSite=Strict")
	}
}

func TestServeHTTP_InvalidToken(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")

	req := httptest.NewRequest("GET", "http://example.com?token=invalid-token", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestServeHTTP_MissingToken(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestServeHTTP_ValidCookie(t *testing.T) {
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")

	tokenHash := hashToken("valid-token")
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	req.AddCookie(&http.Cookie{
		Name:  "auth_session",
		Value: tokenHash,
	})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("Next handler should have been called")
	}

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestServeHTTP_InvalidCookie(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	req.AddCookie(&http.Cookie{
		Name:  "auth_session",
		Value: "invalid-hash",
	})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestRateLimiter_Basic(t *testing.T) {
	rl := NewAuthRateLimiter()

	if rl.isBlocked("192.168.1.1") {
		t.Error("New IP should not be blocked")
	}

	// Record 4 failed attempts
	for i := 0; i < 4; i++ {
		rl.recordFailedAttempt("192.168.1.1")
	}

	if rl.isBlocked("192.168.1.1") {
		t.Error("IP should not be blocked after 4 attempts")
	}

	// 5th attempt should trigger block
	rl.recordFailedAttempt("192.168.1.1")

	if !rl.isBlocked("192.168.1.1") {
		t.Error("IP should be blocked after 5 attempts")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewAuthRateLimiter()

	// Record 5 failed attempts
	for i := 0; i < 5; i++ {
		rl.recordFailedAttempt("192.168.1.1")
	}

	if !rl.isBlocked("192.168.1.1") {
		t.Error("IP should be blocked after 5 attempts")
	}

	// Manually set lastTry to more than 1 hour ago
	rl.mu.Lock()
	rl.lastTry["192.168.1.1"] = time.Now().Add(-2 * time.Hour)
	rl.mu.Unlock()

	if rl.isBlocked("192.168.1.1") {
		t.Error("IP should not be blocked after 1 hour")
	}
}

func TestRateLimiter_MultipleIPs(t *testing.T) {
	rl := NewAuthRateLimiter()

	// Block first IP
	for range 5 {
		rl.recordFailedAttempt("192.168.1.1")
	}

	// Second IP should not be affected
	if rl.isBlocked("192.168.1.2") {
		t.Error("Different IP should not be blocked")
	}

	// Second IP can also be blocked independently
	for range 5 {
		rl.recordFailedAttempt("192.168.1.2")
	}

	if !rl.isBlocked("192.168.1.1") {
		t.Error("First IP should still be blocked")
	}

	if !rl.isBlocked("192.168.1.2") {
		t.Error("Second IP should now be blocked")
	}
}

func TestRateLimiter_MaxEntries(t *testing.T) {
	rl := NewAuthRateLimiter()

	// Fill up to max entries
	for i := range maxRateLimitEntries {
		ip := "192.168.1." + string(rune(i%256))
		rl.recordFailedAttempt(ip)
	}

	rl.mu.RLock()
	count := len(rl.attempts)
	rl.mu.RUnlock()

	if count > maxRateLimitEntries {
		t.Errorf("Should not exceed max entries %d, got %d", maxRateLimitEntries, count)
	}

	// Adding one more should trigger eviction
	rl.recordFailedAttempt("10.0.0.1")

	rl.mu.RLock()
	count = len(rl.attempts)
	rl.mu.RUnlock()

	if count > maxRateLimitEntries {
		t.Errorf("Should not exceed max entries after eviction %d, got %d", maxRateLimitEntries, count)
	}
}

func TestServeHTTP_RateLimitBlocked(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called when rate limited")
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")
	ta := handler.(*tokenAuth)

	// Manually block an IP
	for i := 0; i < 5; i++ {
		ta.rateLimiter.recordFailedAttempt("192.168.1.1")
	}

	req := httptest.NewRequest("GET", "http://example.com?token=valid-token", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, rr.Code)
	}
}

func TestRateLimiter_LRUEviction(t *testing.T) {
	rl := NewAuthRateLimiter()

	// Add entries with different access times
	rl.recordFailedAttempt("192.168.1.1")
	time.Sleep(10 * time.Millisecond)
	rl.recordFailedAttempt("192.168.1.2")
	time.Sleep(10 * time.Millisecond)
	rl.recordFailedAttempt("192.168.1.3")

	// Manually fill to max entries (accounting for 3 already added)
	rl.mu.Lock()
	for i := range maxRateLimitEntries - 3 {
		ip := "10.0.0." + string(rune(i))
		rl.attempts[ip] = 1
		rl.lastTry[ip] = time.Now()
		rl.lastAccess[ip] = time.Now()
	}
	rl.mu.Unlock()

	// Verify we're at max
	rl.mu.RLock()
	initialCount := len(rl.attempts)
	rl.mu.RUnlock()

	if initialCount != maxRateLimitEntries {
		t.Fatalf("Expected %d entries, got %d", maxRateLimitEntries, initialCount)
	}

	// Adding a new IP should trigger eviction of the oldest (192.168.1.1)
	rl.recordFailedAttempt("10.10.10.10")

	rl.mu.RLock()
	finalCount := len(rl.attempts)
	_, hasOldest := rl.attempts["192.168.1.1"]
	_, hasNew := rl.attempts["10.10.10.10"]
	rl.mu.RUnlock()

	if finalCount != maxRateLimitEntries {
		t.Errorf("Should maintain max entries %d, got %d", maxRateLimitEntries, finalCount)
	}

	if hasOldest {
		t.Error("Oldest entry (192.168.1.1) should have been evicted")
	}

	if !hasNew {
		t.Error("New entry (10.10.10.10) should be present")
	}
}

func TestRateLimiter_EvictOldestEntry(t *testing.T) {
	rl := NewAuthRateLimiter()

	// Test eviction with multiple entries
	rl.mu.Lock()
	now := time.Now()
	rl.attempts["192.168.1.1"] = 3
	rl.lastTry["192.168.1.1"] = now.Add(-3 * time.Minute)
	rl.lastAccess["192.168.1.1"] = now.Add(-3 * time.Minute)

	rl.attempts["192.168.1.2"] = 2
	rl.lastTry["192.168.1.2"] = now.Add(-2 * time.Minute)
	rl.lastAccess["192.168.1.2"] = now.Add(-2 * time.Minute)

	rl.attempts["192.168.1.3"] = 1
	rl.lastTry["192.168.1.3"] = now.Add(-1 * time.Minute)
	rl.lastAccess["192.168.1.3"] = now.Add(-1 * time.Minute)

	// Evict oldest (should remove 192.168.1.1)
	rl.evictOldestEntry()

	_, exists1 := rl.attempts["192.168.1.1"]
	_, exists2 := rl.attempts["192.168.1.2"]
	_, exists3 := rl.attempts["192.168.1.3"]
	rl.mu.Unlock()

	if exists1 {
		t.Error("Oldest entry (192.168.1.1) should have been evicted")
	}

	if !exists2 {
		t.Error("Entry 192.168.1.2 should still exist")
	}

	if !exists3 {
		t.Error("Entry 192.168.1.3 should still exist")
	}
}

func TestRateLimiter_EvictOldestEntryEmpty(t *testing.T) {
	rl := NewAuthRateLimiter()

	// Test eviction with empty maps (should not panic)
	rl.mu.Lock()
	rl.evictOldestEntry()
	count := len(rl.attempts)
	rl.mu.Unlock()

	if count != 0 {
		t.Errorf("Empty rate limiter should have 0 entries, got %d", count)
	}
}

func TestIsTokenValid(t *testing.T) {
	config := &Config{
		AllowedTokens: []string{"token1", "token2"},
	}

	ta := &tokenAuth{
		allowedTokens: config.AllowedTokens,
	}

	// Test plaintext token validation
	if !ta.isTokenValid("token1", false) {
		t.Error("Valid token1 should be accepted")
	}

	if !ta.isTokenValid("token2", false) {
		t.Error("Valid token2 should be accepted")
	}

	if ta.isTokenValid("token3", false) {
		t.Error("Invalid token should be rejected")
	}

	// Test hash validation
	hash1 := hashToken("token1")
	if !ta.isTokenValid(hash1, true) {
		t.Error("Valid token hash should be accepted")
	}

	if ta.isTokenValid("invalid-hash", true) {
		t.Error("Invalid token hash should be rejected")
	}
}

func TestIsTokenValid_EmptyAllowedTokens(t *testing.T) {
	ta := &tokenAuth{
		allowedTokens: []string{},
	}

	if ta.isTokenValid("any-token", false) {
		t.Error("Should reject all tokens when allowedTokens is empty")
	}
}

func TestRedirectURLCleansUp(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &Config{
		TokenParam:    "token",
		CookieName:    "auth_session",
		AllowedTokens: []string{"valid-token"},
	}

	handler, _ := New(context.Background(), nextHandler, config, "test")

	req := httptest.NewRequest("GET", "http://example.com/path?token=valid-token&other=param", nil)
	req.Header.Set("X-Real-IP", "192.168.1.1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("Expected redirect location")
	}

	if strings.Contains(location, "token=") {
		t.Error("Token should be removed from redirect URL")
	}

	if !strings.Contains(location, "other=param") {
		t.Error("Other query parameters should be preserved")
	}
}
