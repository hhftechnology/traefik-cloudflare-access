# Traefik Cloudflare Access Plugin

A Traefik middleware plugin that provides authentication through Cloudflare Access by verifying JWT tokens.

## Features

- JWT token verification against Cloudflare Access
- Support for both header and cookie-based tokens
- Configurable team domain and policy audience
- Custom block page for unauthorized access
- Comprehensive error handling and logging

## Configuration

### Static Configuration

```yaml
experimental:
  plugins:
    cloudflare-access:
      moduleName: github.com/hhftechnology/traefik-cloudflare-access
      version: v1.0.0
```

### Dynamic Configuration

```yaml
http:
  middlewares:
    cloudflare-auth:
      plugin:
        cloudflare-access:
          teamDomain: "https://myteam.cloudflareaccess.com"
          policyAUD: "your-policy-audience-tag"
          skipClientIDCheck: false
          skipExpiryCheck: false
          blockPageTitle: "Access Denied"
          blockPageMessage: "You don't have permission to access this resource."

  routers:
    protected-route:
      rule: "Host(`example.com`)"
      service: my-service
      middlewares:
        - cloudflare-auth
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `teamDomain` | string | Yes | - | Your Cloudflare Access team domain |
| `policyAUD` | string | Yes | - | Application Audience (AUD) tag from Cloudflare Access |
| `skipClientIDCheck` | bool | No | false | Skip audience validation |
| `skipExpiryCheck` | bool | No | false | Skip token expiry validation |
| `blockPageTitle` | string | No | "Access Denied" | Title for the block page |
| `blockPageMessage` | string | No | Default message | Message shown on the block page |

## Usage

1. Set up your Cloudflare Access application
2. Note your team domain and policy AUD
3. Configure Traefik with the plugin
4. Add the middleware to your routes

## Token Sources

The plugin looks for JWT tokens in the following order:

1. `Cf-Access-Jwt-Assertion` header
2. `CF_AUTHORIZATION` cookie

## Block Page

When authentication fails, the plugin displays a customizable HTML block page with:

- Custom title and message
- Error details for debugging
- Responsive design
- Cloudflare Access branding

## Development

### Testing

```bash
go test -v ./...
```

### Linting

```bash
golangci-lint run
```

### Building

```bash
go build ./...
```

## License

Apache License 2.0