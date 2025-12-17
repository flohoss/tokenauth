package token

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

const MinTokenLength = 32

func ValidateTokenLength(token string) error {
	if len(token) < MinTokenLength {
		return fmt.Errorf("token must be at least %d characters, got %d", MinTokenLength, len(token))
	}
	return nil
}

type Token struct {
	AllowedTokens []string
	hashedTokens  map[string]bool
}

func New(allowedTokens []string) *Token {
	hashedTokens := make(map[string]bool, len(allowedTokens))
	for _, t := range allowedTokens {
		hashedTokens[HashToken(t)] = true
	}

	return &Token{
		AllowedTokens: allowedTokens,
		hashedTokens:  hashedTokens,
	}
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (t *Token) Valid(value string, isHash bool) bool {
	if len(t.AllowedTokens) == 0 {
		return false
	}

	providedHash := value
	if !isHash {
		providedHash = HashToken(value)
	}

	for hash := range t.hashedTokens {
		if subtle.ConstantTimeCompare([]byte(providedHash), []byte(hash)) == 1 {
			return true
		}
	}
	return false
}
