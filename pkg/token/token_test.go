package token

import "testing"

func TestValidateTokenLength(t *testing.T) {
	tests := []struct {
		token string
		valid bool
	}{
		{"short", false},
		{"a", false},
		{string(make([]byte, 31)), false},
		{string(make([]byte, 32)), true},
		{string(make([]byte, 100)), true},
	}

	for _, tt := range tests {
		err := ValidateTokenLength(tt.token)
		if tt.valid && err != nil {
			t.Errorf("ValidateTokenLength(%s) should be valid, got error: %v", tt.token, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("ValidateTokenLength(%s) should be invalid", tt.token)
		}
	}
}

func TestHashToken(t *testing.T) {
	token := "secret-token"
	hash1 := HashToken(token)
	hash2 := HashToken(token)

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
	allowedTokens := []string{"token1", "token2"}
	tok := New(allowedTokens)

	if tok == nil {
		t.Fatal("Token should not be nil")
	}

	if len(tok.AllowedTokens) != 2 {
		t.Errorf("Expected 2 allowed tokens, got %d", len(tok.AllowedTokens))
	}

	if tok.AllowedTokens[0] != "token1" {
		t.Errorf("Expected first token 'token1', got '%s'", tok.AllowedTokens[0])
	}

	if len(tok.hashedTokens) != 2 {
		t.Errorf("Expected 2 hashed tokens precomputed, got %d", len(tok.hashedTokens))
	}

	hash1 := HashToken("token1")
	if !tok.hashedTokens[hash1] {
		t.Error("Token1 hash should be precomputed and stored in map")
	}
}

func TestValid_WithPlaintext(t *testing.T) {
	tok := New([]string{"valid-token", "another-token"})

	if !tok.Valid("valid-token", false) {
		t.Error("Should validate correct plaintext token")
	}

	if !tok.Valid("another-token", false) {
		t.Error("Should validate second correct plaintext token")
	}

	if tok.Valid("invalid-token", false) {
		t.Error("Should reject invalid plaintext token")
	}
}

func TestValid_WithHash(t *testing.T) {
	tok := New([]string{"valid-token"})
	validHash := HashToken("valid-token")
	invalidHash := HashToken("invalid-token")

	if !tok.Valid(validHash, true) {
		t.Error("Should validate correct token hash")
	}

	if tok.Valid(invalidHash, true) {
		t.Error("Should reject invalid token hash")
	}
}

func TestValid_EmptyAllowedTokens(t *testing.T) {
	tok := New([]string{})

	if tok.Valid("any-token", false) {
		t.Error("Should reject all tokens when allowed list is empty")
	}
}

func TestValid_EmptyValue(t *testing.T) {
	tok := New([]string{"valid-token"})

	if tok.Valid("", false) {
		t.Error("Should reject empty token value")
	}

	if tok.Valid("", true) {
		t.Error("Should reject empty hash value")
	}
}

func TestValid_CaseSensitive(t *testing.T) {
	tok := New([]string{"ValidToken"})

	if !tok.Valid("ValidToken", false) {
		t.Error("Should validate exact case match")
	}

	if tok.Valid("validtoken", false) {
		t.Error("Should reject different case")
	}

	if tok.Valid("VALIDTOKEN", false) {
		t.Error("Should reject uppercase variation")
	}
}
