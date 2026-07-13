---
name: phala-auth
description: Authenticate with Phala Cloud, manage API keys and profiles. Use when the user wants to log in, check auth status, switch profiles, or manage Phala Cloud credentials.
---

# Phala Auth — Authentication & Profiles

## When to use
- User wants to log in to Phala Cloud
- User needs to check authentication status
- User wants to manage multiple Phala Cloud profiles/workspaces
- User needs to set up API keys for CI/CD

## Prerequisites
- Phala CLI installed (`phala --help` to check)
- Install with: `npm install -g phala`

## Environment setup
Load credentials from `.env` if available:
```bash
source .env  # loads PHALA_CLOUD_API_KEY if set
```
If `PHALA_CLOUD_API_KEY` is set, it overrides stored credentials for all commands.

## Commands

### Login (browser device flow — recommended)
```bash
phala login
```
Opens your browser for OAuth. Credentials stored in `~/.phala-cloud/credentials.json`.

### Login with API key (CI/CD or headless)
```bash
phala login $PHALA_CLOUD_API_KEY --manual
```
API keys are prefixed with `phak_`. Generate one at https://cloud.phala.com.

### Login without opening browser
```bash
phala login --no-open
```

### Login to a named profile
```bash
phala login --profile my-workspace
```

### Check authentication status
```bash
phala status
```

### Show current user
```bash
phala whoami
```

### List all profiles
```bash
phala profiles
```

### Switch between profiles
```bash
phala switch <profile-name>
```

### Logout
```bash
phala logout
```

### Print token to stdout (for piping)
```bash
phala login --print-token
```

### Override API endpoint (self-hosted)
```bash
phala login --url https://custom-cloud.example.com
```

## Environment variables
| Variable | Purpose |
|----------|---------|
| `PHALA_CLOUD_API_KEY` | Override stored API key for all commands |
| `PHALA_CLOUD_API_PREFIX` | Override API base URL |
| `PHALA_CLOUD_DIR` | Override credentials directory (default: `~/.phala-cloud`) |

## Global flags (work with all phala commands)
| Flag | Purpose |
|------|---------|
| `--json` | Output as JSON for scripting |
| `--api-token <token>` | Override credentials for a single command |
| `--api-version <version>` | Specify API version (e.g., `2026-01-21`) |

## Security notes
- Credentials are stored in `~/.phala-cloud/credentials.json` with `600` permissions
- Profile-specific creds go in `~/.phala-cloud/profiles/<profile>.json`
- NEVER commit API keys to git — use `.env` or `--api-token` flag
- For CI/CD, store `PHALA_CLOUD_API_KEY` as a repository secret
