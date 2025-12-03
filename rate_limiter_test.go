package token_auth

import (
	"testing"
	"time"
)

func TestRateLimiter_BasicBlocking(t *testing.T) {
	rl := NewAuthRateLimiter()
	ip := "192.168.1.1"

	if rl.isBlocked(ip) {
		t.Error("IP should not be blocked initially")
	}

	for i := 0; i < 5; i++ {
		rl.recordFailedAttempt(ip, 1000)
	}

	if !rl.isBlocked(ip) {
		t.Error("IP should be blocked after 5 attempts")
	}
}

func TestRateLimiter_TimeReset(t *testing.T) {
	rl := NewAuthRateLimiter()
	ip := "192.168.1.1"

	for i := 0; i < 5; i++ {
		rl.recordFailedAttempt(ip, 1000)
	}

	if !rl.isBlocked(ip) {
		t.Error("IP should be blocked")
	}

	rl.mu.Lock()
	rl.lastTry[ip] = time.Now().Add(-2 * time.Hour)
	rl.mu.Unlock()

	if rl.isBlocked(ip) {
		t.Error("IP should be unblocked after time reset")
	}
}

func TestRateLimiter_LRUEviction(t *testing.T) {
	rl := NewAuthRateLimiter()
	maxEntries := 10

	for i := 0; i < maxEntries; i++ {
		ip := "192.168.1." + string(rune('0'+i))
		rl.recordFailedAttempt(ip, maxEntries)
	}

	rl.mu.RLock()
	count := len(rl.attempts)
	rl.mu.RUnlock()

	if count != maxEntries {
		t.Errorf("Expected %d entries, got %d", maxEntries, count)
	}

	newIP := "192.168.1.99"
	rl.recordFailedAttempt(newIP, maxEntries)

	rl.mu.RLock()
	count = len(rl.attempts)
	rl.mu.RUnlock()

	if count > maxEntries {
		t.Errorf("Should not exceed max entries, got %d", count)
	}
}

func TestRateLimiter_MultipleIPs(t *testing.T) {
	rl := NewAuthRateLimiter()
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	for i := 0; i < 5; i++ {
		rl.recordFailedAttempt(ip1, 1000)
	}

	if !rl.isBlocked(ip1) {
		t.Error("IP1 should be blocked")
	}

	if rl.isBlocked(ip2) {
		t.Error("IP2 should not be blocked")
	}
}
