# Lego SCP Challenge Solver

A Go project that uses the lego ACME client library with a custom challenge solver for webroot method using SCP upload.

## Setup

1. Set environment variables:
```bash
export LEGO_SCP_HOST="your-server.com"
export LEGO_SCP_USER="your-username"
export LEGO_SCP_KEY_PATH="/path/to/your/ssh/private/key"
export LEGO_SCP_WEBROOT_PATH="/var/www/html"
export LEGO_SCP_EMAIL="your-email@example.com"
export LEGO_SCP_DOMAINS="example.com,www.example.com"
export LEGO_SCP_ACCOUNT_KEY="/path/to/account.key"
export LEGO_SCP_CERT_PATH="/path/to/certificates"
```

2. Install dependencies:
```bash
go mod tidy
```

3. Run with environment variables:
```bash
go run .
```

Or with command-line flags:
```bash
go run . -e your-email@example.com -d example.com,www.example.com -k /path/to/account.key \
  --scp-host your-server.com --scp-user username --scp-key ~/.ssh/id_rsa --scp-webroot /var/www/html \
  --cert-path ./certificates
```

## Command-line flags

| Flag | Short | Environment Variable | Description |
|------|-------|----------------------|-------------|
| `--email` | `-e` | `LEGO_SCP_EMAIL` | Email address for ACME registration |
| `--domains` | `-d` | `LEGO_SCP_DOMAINS` | Comma-separated list of domains |
| `--account-key` | `-k` | `LEGO_SCP_ACCOUNT_KEY` | Path to ACME account private key (default: "account.key") |
| `--scp-host` | | `LEGO_SCP_HOST` | SCP server hostname |
| `--scp-user` | | `LEGO_SCP_USER` | SCP username |
| `--scp-key` | | `LEGO_SCP_KEY_PATH` | Path to SSH private key for SCP |
| `--scp-webroot` | | `LEGO_SCP_WEBROOT_PATH` | Remote webroot path for challenge files |
| `--cert-path` | | `LEGO_SCP_CERT_PATH` | Directory to save certificates (default: current directory) |

## How it works

- Implements HTTP-01 challenge using SCP to upload challenge files
- Creates `.well-known/acme-challenge/` directory on remote server
- Uploads challenge token file via SSH
- Cleans up after verification
- Supports multiple domains (comma-separated)

## Building

```bash
# Build for current platform
make build

# Install to GOPATH
make install

# Cross-compile for different platforms
make build-all

# Clean up
make clean
```