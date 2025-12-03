package token_auth

import "net/http"

type CookieConfig struct {
	Name     string
	HttpOnly bool
	Secure   bool
	SameSite string
	MaxAge   int
}

func parseSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "Lax":
		return http.SameSiteLaxMode
	case "Strict":
		return http.SameSiteStrictMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

func defaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     "auth_session",
		HttpOnly: true,
		Secure:   true,
		SameSite: "Strict",
		MaxAge:   0,
	}
}
