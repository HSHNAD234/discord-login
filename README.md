# HSHONAD Discord Login Backend

Node.js backend for HSHONAD Launcher Discord OAuth and whitelist verification.

## Required Render environment variables

- `BASE_URL`: public HTTPS URL of this Render web service, without a trailing slash.
- `DATABASE_URL`: Render PostgreSQL **internal connection string** when the database and service share a region/workspace.
- `DISCORD_CLIENT_ID`: Discord OAuth application client ID.
- `DISCORD_CLIENT_SECRET`: Discord OAuth application client secret.
- `GOOGLE_SHEET_ID`: Google spreadsheet ID containing the whitelist.
- `GOOGLE_SERVICE_ACCOUNT_JSON`: service account JSON as a single environment-variable value.
- `SHEET_RANGE` (optional): whitelist range; defaults to `ชีต1!D2:D`.

Set the Discord OAuth redirect URI to `<BASE_URL>/auth/discord/callback`.

## PostgreSQL and saved sessions

On startup the service creates the required tables if they do not exist. The raw launcher session token is returned once by the claim endpoint; only its SHA-256 hash is stored in PostgreSQL. The launcher stores the raw token encrypted for the current Windows user using DPAPI.

The saved launcher session expires after 30 days. Each Auto Login calls `GET /api/launcher/sessions/validate`, which checks the session and rechecks the current Google Sheets whitelist. A whitelist removal revokes the saved session. `POST /api/launcher/sessions/revoke` supports logout.

Device sessions and OAuth state remain short-lived in process memory (10 minutes); only persistent launcher sessions and Discord cooldown state are stored in PostgreSQL. Use a single web-service instance for the device OAuth flow unless device-session state is also moved to shared storage.

## Rate-limit handling

When Discord returns HTTP 429, the service honors `Retry-After` (or Discord's `retry_after` body value), stores the cooldown in PostgreSQL, and blocks new OAuth starts until it expires. Do not manually retry token exchange or reuse an OAuth authorization code.

## Local checks

```sh
npm install
npm run check
npm start
```
