# Token Authentication Middleware for Traefik

A Traefik middleware plugin that provides token-based authentication with secure session management.

## Features

- Token-based authentication via query parameters
- Secure session cookies with SHA-256 hashed tokens
- Enforced token strength (minimum 32 characters)
- Token parameter takes priority over stored cookies
- Automatic URL cleanup (removes token from URL after authentication)
- HttpOnly, Secure, and SameSite cookie protection
- Configurable error handling: redirect to custom page or return 403 Forbidden
- Constant-time token comparison to prevent timing attacks

## Installation

### Static Configuration

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    tokenauth:
      moduleName: github.com/flohoss/tokenauth
      version: v0.4.0
```

Or with Docker labels:

```yaml
labels:
  - 'traefik.experimental.plugins.tokenauth.modulename=github.com/flohoss/tokenauth'
  - 'traefik.experimental.plugins.tokenauth.version=v0.4.0'
```

### Dynamic Configuration

Configure the middleware in your dynamic configuration:

```yaml
# config.yml
http:
  middlewares:
    my-tokenauth:
      plugin:
        tokenauth:
          tokenParam: 'token'
          cookie:
            name: 'auth_session'
            httpOnly: true
            secure: true
            sameSite: 'Strict'
            maxAge: 0
          allowedTokens:
            - 'your-secret-token-abcdefghij1234'
            - 'your-secret-token-abcdefghij5678'
```

Or with Docker labels:

```yaml
labels:
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.tokenParam=token'
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.cookie.name=auth_session'
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.cookie.httpOnly=true'
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.cookie.secure=true'
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.cookie.sameSite=Strict'
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.cookie.maxAge=0'
  - 'traefik.http.middlewares.tokenauth.plugin.tokenauth.allowedTokens[0]=your-secret-token-abcdefghij1234'
```

## Token Requirements

**Minimum Token Length: 32 characters**

The middleware enforces a minimum token length of 32 characters to prevent weak tokens from being used. This ensures tokens are strong enough to resist brute-force attacks.

Examples of valid tokens:

```
✓ abcdefghijklmnopqrstuvwxyz012345  (exactly 32 characters)
✓ a-super-long-secure-token-with-many-characters-for-extra-security
```

Invalid tokens:

```
✗ short-token               (too short)
✗ mytoken                   (too short)
```

### Generating Secure Tokens

Generate tokens using cryptographically secure methods:

```bash
openssl rand -base64 32
```

### Apply to Routes

```yaml
http:
  routers:
    my-router:
      rule: 'Host(`example.com`)'
      service: my-service
      middlewares:
        - my-tokenauth
```

Or with Docker:

```yaml
labels:
  - 'traefik.http.routers.my-router.rule=Host(`example.com`)'
  - 'traefik.http.routers.my-router.middlewares=tokenauth'
```

## Configuration Options

| Parameter          | Type     | Default          | Description                                               |
| ------------------ | -------- | ---------------- | --------------------------------------------------------- |
| `tokenParam`       | string   | `"token"`        | Query parameter name for the authentication token         |
| `errorRedirectURL` | string   | empty            | Absolute URL for auth failures (must include scheme like https:// or http://, e.g., https://example.com/error) |
| `cookie.name`      | string   | `"auth_session"` | Name of the session cookie                                |
| `cookie.httpOnly`  | bool     | `true`           | Set HttpOnly flag on cookies                              |
| `cookie.secure`    | bool     | `true`           | Set Secure flag on cookies (requires HTTPS)               |
| `cookie.sameSite`  | string   | `"Strict"`       | SameSite attribute: "Strict", "Lax", or "None"            |
| `cookie.maxAge`    | int      | `0`              | Cookie max age in seconds (0 = session cookie)            |
| `allowedTokens`    | []string | `[]`             | List of valid authentication tokens                       |

## Security

### Token Length Enforcement

Tokens are enforced to be at least 32 characters long, preventing weak tokens from being used. Configuration with shorter tokens will fail at startup with a clear error message.

### Failed Attempt Handling

When a request fails authentication (invalid token or missing cookie), the middleware either:
- Redirects to the configured `errorRedirectURL` with `HTTP 303 See Other`, or
- Returns `HTTP 403 Forbidden` with plain text response (if no redirect URL configured)

The response does not reveal whether the failure was due to invalid token format, token not found, or expired session, preventing attackers from learning about your authentication mechanism.

### Error Responses

### Error Responses

When authentication fails, the middleware handles it in one of two ways:

**Option 1: Custom Error Redirect (Recommended)**

Redirect to an absolute URL with full scheme and host:

```yaml
middlewares:
  my-tokenauth:
    plugin:
      tokenauth:
        tokenParam: token
        errorRedirectURL: https://example.com/access-denied
        allowedTokens:
          - your-secret-token-abcdefghij1234
```

Or with port:

```yaml
errorRedirectURL: http://localhost:8080/error
```

Users are redirected with `HTTP 303 See Other` to your custom error page. The `errorRedirectURL` **must be an absolute URL** (e.g., `https://example.com/error` or `http://localhost:8080/error`) - relative URLs like `/error` are not allowed.

**Option 2: Plain Text 403 Response (Default)**
If `errorRedirectURL` is not configured, users receive:
- **Status Code**: `HTTP 403 Forbidden`
- **Body**: Plain text "Forbidden"
- No HTML page, minimal response footprint

### Recommended Security Practices

1. **Use HTTPS**: The middleware sets the `Secure` flag on cookies, requiring HTTPS
2. **Strong Tokens**: Generate tokens with cryptographically secure randomness (minimum 32 characters, recommended 64+)
3. **Token Storage**: Never commit tokens to version control - use environment variables
4. **Token Rotation**: Regularly rotate authentication tokens
5. **Monitoring**: Monitor for unusual authentication patterns
6. **Rate Limiting**: Consider implementing external rate limiting (e.g., Traefik middleware) for additional protection

### Constant-Time Comparison

Token validation uses constant-time comparison to prevent timing-based attacks that could leak token information.

## Usage

### First-Time Authentication

1. User visits: `https://example.com?token=your-secret-token-abcdefghij1234`
2. Middleware validates the token
3. Token is hashed (SHA-256) and stored in a secure cookie
4. User is redirected to: `https://example.com` (clean URL)

### Subsequent Requests

- The middleware checks for the session cookie
- If valid, access is granted immediately
- No token in URL is needed for authenticated sessions

### Session Cookie Details

- **Duration**: Configurable via `cookieMaxAge` (default: session cookie that expires when browser closes)
- **Security**: Configurable via `cookieHttpOnly`, `cookieSecure`, `cookieSameSite` (defaults: HttpOnly=true, Secure=true, SameSite=Strict)
- **Storage**: SHA-256 hash of the token (not plaintext)

**Example: Persistent cookie for 30 days**

```yaml
middlewares:
  my-tokenauth:
    plugin:
      tokenauth:
        cookie:
          maxAge: 2592000 # 30 days in seconds
        # ... other config
```

## Authentication Flow

The middleware implements the following authentication priority:

1. **Token Parameter (Highest Priority)**: If a token is provided in the query parameter:

   - Validates the token against the allowed tokens list
   - On success: Sets the session cookie with hashed token and redirects with `HTTP 307 Temporary Redirect` (clean URL)
   - On failure: Redirects to `errorRedirectURL` with `HTTP 303 See Other`, or returns `HTTP 403 Forbidden` (if no redirect URL)

2. **Session Cookie**: If no token is in the query:
   - Checks for a valid session cookie
   - On success: Grants access to the protected resource
   - On failure: Redirects to `errorRedirectURL` with `HTTP 303 See Other`, or returns `HTTP 403 Forbidden` (if no redirect URL)

This ensures that providing a token always validates it, even if a previous valid cookie exists.

## Security Considerations

1. **Use HTTPS**: The middleware sets the `Secure` flag on cookies, requiring HTTPS
2. **Strong Tokens**: Use cryptographically random tokens (e.g., 32+ characters)
3. **Token Storage**: Never expose `allowedTokens` in public repositories
4. **Environment Variables**: Consider loading tokens from environment variables
5. **Token Rotation**: Regularly rotate authentication tokens
