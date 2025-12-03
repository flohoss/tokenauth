package token_auth

import (
	"sync"
	"time"
)

type AuthRateLimiter struct {
	attempts map[string]int
	lastTry  map[string]time.Time
	mu       sync.RWMutex
}

func NewAuthRateLimiter() *AuthRateLimiter {
	return &AuthRateLimiter{
		attempts: make(map[string]int),
		lastTry:  make(map[string]time.Time),
	}
}

func (rl *AuthRateLimiter) isBlocked(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	attempts, exists := rl.attempts[ip]
	if !exists {
		return false
	}

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
}

func (rl *AuthRateLimiter) recordFailedAttempt(ip string, maxEntries int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.attempts) >= maxEntries {
		if _, exists := rl.attempts[ip]; !exists {
			rl.evictOldestEntry()
		}
	}

	now := time.Now()
	rl.attempts[ip]++
	rl.lastTry[ip] = now
}

func (rl *AuthRateLimiter) evictOldestEntry() {
	if len(rl.lastTry) == 0 {
		return
	}

	var oldestIP string
	var oldestTime time.Time
	first := true

	for ip, tryTime := range rl.lastTry {
		if first || tryTime.Before(oldestTime) {
			oldestIP = ip
			oldestTime = tryTime
			first = false
		}
	}

	if oldestIP != "" {
		delete(rl.attempts, oldestIP)
		delete(rl.lastTry, oldestIP)
	}
}
