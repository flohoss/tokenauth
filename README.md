# Token Authentication Middleware for Traefik

A Traefik middleware plugin that provides token-based authentication with secure session management and rate limiting.

## Features

- Token-based authentication via query parameters
- Secure session cookies with SHA-256 hashed tokens
- Built-in rate limiting (5 failed attempts per hour per IP)
- Automatic URL cleanup (removes token from URL after authentication)
- HttpOnly, Secure, and SameSite cookie protection

## Installation

### Static Configuration

Add the plugin to your Traefik static configuration:

```yaml
# traefik.yml
experimental:
  plugins:
    token-auth:
      moduleName: github.com/flohoss/token-auth
      version: v1.0.0
```

Or with Docker labels:

```yaml
labels:
  - 'traefik.experimental.plugins.token-auth.modulename=github.com/flohoss/token-auth'
  - 'traefik.experimental.plugins.token-auth.version=v1.0.0'
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
          cookieName: 'auth_session'
          allowedTokens:
            - 'your-secret-token-1'
            - 'your-secret-token-2'
```

Or with Docker labels:

```yaml
labels:
  - 'traefik.http.middlewares.my-token-auth.plugin.token-auth.tokenParam=token'
  - 'traefik.http.middlewares.my-token-auth.plugin.token-auth.cookieName=auth_session'
  - 'traefik.http.middlewares.my-token-auth.plugin.token-auth.allowedTokens[0]=your-secret-token-1'
  - 'traefik.http.middlewares.my-token-auth.plugin.token-auth.allowedTokens[1]=your-secret-token-2'
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

| Parameter       | Type     | Default          | Description                                       |
| --------------- | -------- | ---------------- | ------------------------------------------------- |
| `tokenParam`    | string   | `"token"`        | Query parameter name for the authentication token |
| `cookieName`    | string   | `"auth_session"` | Name of the session cookie                        |
| `allowedTokens` | []string | `[]`             | List of valid authentication tokens               |

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

- **Duration**: Session cookie (expires when browser closes)
- **Security**: HttpOnly, Secure, SameSite=Strict
- **Storage**: SHA-256 hash of the token (not plaintext)

## Rate Limiting

The middleware includes built-in protection against brute-force attacks:

- **Limit**: 5 failed authentication attempts per IP address
- **Window**: 1 hour
- **Reset**: Automatically resets after 1 hour of the last failed attempt
- **Response**: HTTP 429 "Too many failed attempts. Try again later."

Rate limiting is tracked using the `X-Real-IP` header (set by Traefik).

## Security Considerations

1. **Use HTTPS**: The middleware sets the `Secure` flag on cookies, requiring HTTPS
2. **Strong Tokens**: Use cryptographically random tokens (e.g., 32+ characters)
3. **Token Storage**: Never expose `allowedTokens` in public repositories
4. **Environment Variables**: Consider loading tokens from environment variables
5. **Token Rotation**: Regularly rotate authentication tokens

## Example: Complete Docker Compose Setup

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - '--experimental.plugins.token-auth.modulename=github.com/flohoss/token-auth'
      - '--experimental.plugins.token-auth.version=v1.0.0'
    ports:
      - '80:80'
      - '443:443'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  myapp:
    image: my-application:latest
    labels:
      - 'traefik.enable=true'
      - 'traefik.http.routers.myapp.rule=Host(`app.example.com`)'
      - 'traefik.http.routers.myapp.entrypoints=websecure'
      - 'traefik.http.routers.myapp.tls=true'

      # Token Auth Middleware
      - 'traefik.http.middlewares.auth.plugin.token-auth.tokenParam=token'
      - 'traefik.http.middlewares.auth.plugin.token-auth.cookieName=auth_session'
      - 'traefik.http.middlewares.auth.plugin.token-auth.allowedTokens[0]=replace-with-secure-token'

      # Apply Middleware
      - 'traefik.http.routers.myapp.middlewares=auth@docker'
```

## Troubleshooting

### "Unauthorized" on valid token

- Verify token matches exactly (case-sensitive)
- Check `allowedTokens` configuration
- Ensure no whitespace in token values

### Cookie not persisting

- Verify HTTPS is enabled (required for `Secure` flag)
- Check browser settings for cookie blocking
- Verify domain matches

### Rate limiting triggered unexpectedly

- Check if multiple users share the same `X-Real-IP`
- Consider adjusting rate limit in code if needed
- Verify proxy headers are correctly forwarded

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
