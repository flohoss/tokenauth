# Token Authentication Middleware for Traefik

A Traefik middleware plugin that provides token-based authentication with secure session management and rate limiting.

## Features

- Token-based authentication via query parameters
- Secure session cookies with SHA-256 hashed tokens
- Built-in rate limiting (5 failed attempts per hour per IP)
- Memory-safe with LRU eviction (max 10,000 tracked IPs)
- Automatic URL cleanup (removes token from URL after authentication)
- HttpOnly, Secure, and SameSite cookie protection

## Installation

### Static Configuration

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    token-auth:
      moduleName: github.com/flohoss/token-auth
      version: v0.1.0
```

Or with Docker labels:

```yaml
labels:
  - 'traefik.experimental.plugins.token-auth.modulename=github.com/flohoss/token-auth'
  - 'traefik.experimental.plugins.token-auth.version=v0.1.0'
```

### Dynamic Configuration

Configure the middleware in your dynamic configuration:

```yaml
# config.yml
http:
  middlewares:
    my-token-auth:
      plugin:
        token-auth:
          tokenParam: 'token'
          maxRateLimitEntries: 10000
          cookie:
            name: 'auth_session'
            httpOnly: true
            secure: true
            sameSite: 'Strict'
            maxAge: 0
          allowedTokens:
            - 'your-secret-token-1'
            - 'your-secret-token-2'
```

Or with Docker labels:

```yaml
labels:
  - 'traefik.http.middlewares.auth.plugin.token-auth.tokenParam=token'
  - 'traefik.http.middlewares.auth.plugin.token-auth.maxRateLimitEntries=10000'
  - 'traefik.http.middlewares.auth.plugin.token-auth.cookie.name=auth_session'
  - 'traefik.http.middlewares.auth.plugin.token-auth.cookie.httpOnly=true'
  - 'traefik.http.middlewares.auth.plugin.token-auth.cookie.secure=true'
  - 'traefik.http.middlewares.auth.plugin.token-auth.cookie.sameSite=Strict'
  - 'traefik.http.middlewares.auth.plugin.token-auth.cookie.maxAge=0'
  - 'traefik.http.middlewares.auth.plugin.token-auth.allowedTokens[0]=replace-with-secure-token'
```

### Apply to Routes

```yaml
http:
  routers:
    my-router:
      rule: 'Host(`example.com`)'
      service: my-service
      middlewares:
        - my-token-auth
```

Or with Docker:

```yaml
labels:
  - 'traefik.http.routers.my-router.middlewares=my-token-auth@docker'
```

## Configuration Options

| Parameter              | Type     | Default          | Description                                         |
| ---------------------- | -------- | ---------------- | --------------------------------------------------- |
| `tokenParam`           | string   | `"token"`        | Query parameter name for the authentication token   |
| `maxRateLimitEntries`  | int      | `10000`          | Maximum number of IPs tracked by rate limiter       |
| `cookie.name`          | string   | `"auth_session"` | Name of the session cookie                          |
| `cookie.httpOnly`      | bool     | `true`           | Set HttpOnly flag on cookies                        |
| `cookie.secure`        | bool     | `true`           | Set Secure flag on cookies (requires HTTPS)         |
| `cookie.sameSite`      | string   | `"Strict"`       | SameSite attribute: "Strict", "Lax", or "None"     |
| `cookie.maxAge`        | int      | `0`              | Cookie max age in seconds (0 = session cookie)      |
| `allowedTokens`        | []string | `[]`             | List of valid authentication tokens                 |

## Usage

### First-Time Authentication

1. User visits: `https://example.com?token=your-secret-token-1`
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
  my-token-auth:
    plugin:
      token-auth:
        cookieMaxAge: 2592000  # 30 days in seconds
        # ... other config
```

## Rate Limiting

The middleware includes built-in protection against brute-force attacks:

- **Limit**: 5 failed authentication attempts per IP address
- **Window**: 1 hour
- **Reset**: Automatically resets after 1 hour of the last failed attempt
- **Response**: HTTP 429 "Too many failed attempts. Try again later."
- **Memory Protection**: LRU eviction when tracking limit (10,000 IPs) is reached

Rate limiting is tracked using the `X-Real-IP` header (set by Traefik).

### Memory Safety

The rate limiter implements memory protection to prevent unbounded growth:

- **Max Tracked IPs**: Configurable via `maxRateLimitEntries` (default: 10,000 entries, ~2.4 MB maximum memory)
- **Eviction Policy**: Least Recently Used (LRU) - oldest entries are removed when limit is reached
- **Expired Entries**: Entries older than 1 hour are automatically cleaned up during normal operation

You can adjust the limit based on your needs. Lower values reduce memory usage but may affect rate limiting under heavy load. Higher values provide more tracking capacity but use more memory (~240 bytes per IP).

This ensures the middleware remains memory-efficient even under sustained attacks with rotating IPs.

## Security Considerations

1. **Use HTTPS**: The middleware sets the `Secure` flag on cookies, requiring HTTPS
2. **Strong Tokens**: Use cryptographically random tokens (e.g., 32+ characters)
3. **Token Storage**: Never expose `allowedTokens` in public repositories
4. **Environment Variables**: Consider loading tokens from environment variables
5. **Token Rotation**: Regularly rotate authentication tokens
