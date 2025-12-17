package tokenauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/flohoss/tokenauth/pkg/cookie"
	"github.com/flohoss/tokenauth/pkg/token"
)

type Config struct {
	TokenParam       string              `json:"tokenParam,omitempty"`
	AllowedTokens    []string            `json:"allowedTokens,omitempty"`
	Cookie           cookie.CookieConfig `json:"cookie,omitempty"`
	ErrorRedirectURL string              `json:"errorRedirectURL,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		TokenParam: "token",
		Cookie:     cookie.DefaultCookieConfig(),
	}
}

type tokenAuth struct {
	next             http.Handler
	name             string
	tokenParam       string
	allowedTokens    []string
	token            *token.Token
	cookieConfig     cookie.CookieConfig
	errorRedirectURL string
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

	if config.Cookie.MaxAge < 0 {
		return nil, fmt.Errorf("cookie.MaxAge cannot be negative")
	}

	for _, t := range config.AllowedTokens {
		if err := token.ValidateTokenLength(t); err != nil {
			return nil, err
		}
	}

	if config.ErrorRedirectURL != "" {
		if _, err := url.Parse(config.ErrorRedirectURL); err != nil {
			return nil, fmt.Errorf("errorRedirectURL is not a valid URL: %w", err)
		}
	}

	return &tokenAuth{
		next:             next,
		name:             name,
		tokenParam:       config.TokenParam,
		allowedTokens:    config.AllowedTokens,
		token:            token.New(config.AllowedTokens),
		cookieConfig:     config.Cookie,
		errorRedirectURL: config.ErrorRedirectURL,
	}, nil
}

func (t *tokenAuth) handleAuthFailure(rw http.ResponseWriter, req *http.Request) {
	if t.errorRedirectURL != "" {
		http.Redirect(rw, req, t.errorRedirectURL, http.StatusSeeOther)
		return
	}

	http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func (t *tokenAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	param := req.URL.Query().Get(t.tokenParam)

	if param != "" {
		if !t.token.Valid(param, false) {
			http.SetCookie(rw, cookie.Clear(t.cookieConfig))
			t.handleAuthFailure(rw, req)
			return
		}

		authCookie := cookie.New(t.cookieConfig, token.HashToken(param))
		http.SetCookie(rw, authCookie)

		q := req.URL.Query()
		q.Del(t.tokenParam)

		redirectURL := req.URL.Path
		if len(q) > 0 {
			redirectURL += "?" + q.Encode()
		}

		http.Redirect(rw, req, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	c, err := req.Cookie(t.cookieConfig.Name)
	if err == nil && t.token.Valid(c.Value, true) {
		t.next.ServeHTTP(rw, req)
		return
	}

	t.handleAuthFailure(rw, req)
}
