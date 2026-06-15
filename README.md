# Flomation Sentinel

> Identity and access management (IDaM) service for the Flomation stack — authentication, sessions, and user management.

## Overview

Flomation Sentinel is a Go HTTP service that handles authentication, session management,
and user management for the Flomation stack. It serves the sign-in UI, issues and
validates JWT tokens, and supports a range of authentication methods:

- **Password** sign-in with email verification and password reset
- **Multi-factor authentication** (TOTP) with QR enrolment
- **Passkeys / WebAuthn** registration and login
- **OAuth sign-in** with Google, Microsoft, GitHub, and LinkedIn
- **SSO** via Google and Microsoft (with optional email-domain restrictions)

It persists data in PostgreSQL (running migrations on startup), can send transactional
email over SMTP, performs GeoIP lookups for session context, and exposes Prometheus
metrics.

## Prerequisites

- Go 1.26.1+
- PostgreSQL
- (Optional) An SMTP server for email notifications
- (Optional) OAuth/SSO provider credentials and a GeoIP API key
- Docker (optional, for containerised deployment)

## Installation

```bash
# Clone the repository
git clone <repo-url> && cd sentinel

# Install dependencies
go mod download
```

## Configuration

The service reads a `config.json` file from the working directory on startup. Most fields
can also be supplied via environment variables or CLI arguments.

### Listener

| Field | Env Variable | Description | Default |
|-------|-------------|-------------|---------|
| `address` | `LISTEN_ADDRESS` | Bind address | `127.0.0.1` |
| `port` | `LISTEN_PORT` | Listen port | `8999` |
| `url` | `LISTEN_URL` | Public base URL of the service | — |

### Database

| Field | Env Variable | Description | Required | Default |
|-------|-------------|-------------|----------|---------|
| `hostname` | `DB_HOSTNAME` | PostgreSQL host | Yes | — |
| `port` | `DB_PORT` | PostgreSQL port | Yes | — |
| `username` | `DB_USERNAME` | Database user | Yes | — |
| `password` | `DB_PASSWORD` | Database password | Yes | — |
| `database` | `DB_NAME` | Database name | Yes | — |
| `encryption_key` | `DB_ENCRYPTION_KEY` | Key for encrypting sensitive data | Yes | — |
| `max_idle_connections` | `DB_IDLE_CONNS` | Max idle DB connections | No | `5` |
| `max_open_connections` | `DB_OPEN_CONNS` | Max open DB connections | No | `10` |
| `ssl_mode` | `DB_SSL_MODE` | Override PostgreSQL SSL mode | No | — |

> The database encryption key may also be passed with the `-db-encryption-key` flag. If
> no `auth_secret` is configured, Sentinel generates one and persists it to the database
> on first start.

### Security

| Field | Env Variable | Description | Default |
|-------|-------------|-------------|---------|
| `realm` | `AUTH_REALM` | Authentication realm | `localhost` |
| `secret` | `AUTH_SECRET` | JWT signing secret (auto-generated if unset) | — |
| `login_redirect` | `AUTH_LOGIN_REDIRECT` | Redirect target after login | `http://localhost/` |
| `logout_redirect` | `AUTH_LOGOUT_REDIRECT` | Redirect target after logout | `http://localhost/logout` |
| `cookie.domain` | `COOKIE_DOMAIN` | Session cookie domain | `localhost` |
| `cookie.secure` | — | Set the `Secure` cookie flag | `true` |
| `cookie.http_only` | — | Set the `HttpOnly` cookie flag | — |
| `cookie.expiration` | — | Cookie lifetime (seconds) | `86400` |

### Optional integrations

| Section | Purpose |
|---------|---------|
| `notification` | SMTP email notifications (`SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_PORT`) |
| `geo` | GeoIP lookups (`GEOIP_API_KEY`) |
| `webauthn` | Passkey relying-party settings (`display_name`, `rp_id`, `rp_origins`) |
| `google_oauth` / `microsoft_oauth` / `github_oauth` / `linkedin_oauth` | OAuth sign-in provider credentials |
| `sso` | Google / Microsoft SSO (`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, optional allowed domains) |
| `metrics` | Prometheus `/metrics` endpoint (`METRICS_ENABLED`, allowed IPs) |

Example `config.json`:

```json
{
  "listener": {
    "address": "0.0.0.0",
    "port": 8999,
    "url": "https://id.flomation.app"
  },
  "database": {
    "hostname": "localhost",
    "port": 5432,
    "username": "flomation",
    "password": "secret",
    "database": "sentinel",
    "encryption_key": "your-encryption-key",
    "ssl_mode": "disable"
  },
  "security": {
    "realm": "flomation.app",
    "cookie": { "domain": "flomation.app", "secure": true, "http_only": true },
    "login_redirect": "https://app.flomation.app/",
    "logout_redirect": "https://app.flomation.app/logout"
  },
  "metrics": { "enabled": true, "allowed_ips": ["10.0.0.0/8"] }
}
```

## Usage

```bash
# Run the service
go run ./cmd

# Print version information and exit
go run ./cmd -version
```

The server listens on the configured address and port (default `127.0.0.1:8999`) and
runs any pending database migrations on startup.

## HTTP Endpoints

### Authentication & UI

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Landing / entry page |
| `GET/POST` | `/authenticate` | Sign-in page and credential submission |
| `GET/POST` | `/verify` | Account / email verification |
| `GET/POST` | `/password` | Set or reset password |
| `GET` | `/passkeys` | Manage registered passkeys |
| `GET` | `/logout` | Sign out and clear the session |

### Multi-factor authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/mfa` | MFA management page |
| `GET` | `/mfa/qr` | TOTP enrolment QR code |
| `POST` | `/mfa/enrol` | Begin TOTP enrolment |
| `POST` | `/mfa/verify` | Verify a TOTP code |
| `POST` | `/mfa/disable` | Disable MFA |

### Passkeys (WebAuthn)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/webauthn/register/begin` | Start passkey registration |
| `POST` | `/webauthn/register/finish` | Complete passkey registration |
| `POST` | `/webauthn/login/begin` | Start passkey login |
| `POST` | `/webauthn/login/finish` | Complete passkey login |
| `DELETE` | `/webauthn/credential/:id` | Remove a registered credential |

### OAuth / SSO

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/:provider/login` | Begin OAuth/SSO login with a provider |
| `GET` | `/auth/:provider/callback` | OAuth/SSO provider callback |
| `GET` | `/api/sso/providers` | List enabled SSO providers |

### API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/token` | Issue a JWT token |
| `GET` | `/api/account` | Current account details |
| `GET` | `/api/user` | Get the current user |
| `POST` | `/api/user` | Create a user |
| `PUT` | `/api/user` | Update the current user |
| `GET` | `/api/sessions` | List active sessions |

### Operational

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/version` | Build version, hash, and date |
| `GET` | `/metrics` | Prometheus metrics (when enabled) |

## Development

```bash
# Run tests
make test

# Lint (runs goimports, golangci-lint, go vet, gosec, govulncheck)
make lint

# Build for all platforms (linux, darwin, windows — amd64/arm64/arm)
make build
```

## Docker

Base image: `dhi.io/alpine-base:3.23-alpine3.23-dev`. Runs as a non-root `flomation`
user.

```bash
docker build --build-arg BINARY_FILE=dist/flomation-sentinel-amd64-linux-1.0.dev -t flomation-sentinel .
docker run -p 8999:8999 -v $(pwd)/config.json:/config.json flomation-sentinel
```

## Project Structure

```
.
├── cmd/
│   └── main.go                  # Entry point — config, migrations, listener
├── internal/
│   ├── config/                  # Configuration loading (JSON/env/args)
│   ├── listener/                # HTTP server, routes, and handlers
│   │   ├── authenticate.go      # Password sign-in
│   │   ├── mfa.go               # TOTP multi-factor auth
│   │   ├── webauthn.go          # Passkey registration and login
│   │   ├── oauth.go             # OAuth sign-in providers
│   │   ├── sso.go               # Google / Microsoft SSO
│   │   ├── token.go             # JWT token issuance
│   │   ├── sessions.go          # Session endpoints
│   │   ├── user.go              # User API
│   │   └── middleware.go        # Auth middleware
│   ├── security/                # JWT signing and crypto
│   ├── session/                 # Session management
│   ├── user/                    # User domain logic
│   ├── mfa/                     # TOTP implementation
│   ├── passkey/                 # WebAuthn relying-party logic
│   ├── smtp/                    # Email sending
│   ├── geo/                     # GeoIP lookups
│   ├── metrics/                 # Prometheus metrics collector
│   ├── persistence/             # PostgreSQL access layer and migrations
│   ├── assets/                  # Embedded templates and static files
│   ├── utils/                   # Helpers
│   └── version/                 # Build version info
├── Dockerfile
├── Makefile
└── go.mod
```

## Licence

MIT — Flomation LTD. See [LICENCE.md](LICENCE.md).
