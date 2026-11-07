# Server-side token refresh

`server --refresh-tokens --refresh-accounts id1,id2` lets the server renew an expired stored login through the OAuth token endpoint instead of leaving the card at `unauthorized`. It is OFF by default, and with the flag on it refreshes nothing unless accounts are listed.

## Usage
- `--refresh-accounts` takes comma-separated account ids (the ids used in logs, case-sensitive). Spaces are trimmed; empty entries and duplicates are dropped.
- Fail closed: `--refresh-tokens` with no `--refresh-accounts` (absent or empty) refreshes NOTHING. The server logs `action=refresh result=fail-closed count=0`.
- `--refresh-accounts` without `--refresh-tokens` does nothing; the server logs a WARN `result=ignored` and starts normally.
- At startup the server logs `result=allowlist count=N`, and `result=unmatched count=M` when M listed ids match no stored account (harmless: they never match).
- Restart steps: stop the server, start it again with both flags (`--refresh-tokens --refresh-accounts id1,id2`), then check the log for the allowlist line. The list is read only at start; changing it needs a restart.

## What it does
- On a 401 from the usage endpoint, POSTs JSON `{grant_type, refresh_token, client_id, scope}` to `https://platform.claude.com/v1/oauth/token` (30 s timeout, `Content-Type: application/json`, no other headers).
- Merges the answer into the stored `claudeAiOauth` block: new `accessToken`, new `refreshToken` if returned (else the old one stays), `expiresAt`, `refreshTokenExpiresAt` when given. `mcpOAuth`, `subscriptionType`, `rateLimitTier` and unknown fields are kept. The block is saved with `vault.ReplaceBlock` (a backup is kept).
- An account refreshes only if its id is in `--refresh-accounts` AND it passes the ownership gate `reg.OwnerOf(id).Server`. Ownership is in-memory and empty after a restart, so `OwnerOf(id).Server` is true for every account until a swap or import in that process; host connect or report does not populate it. The allowlist is therefore the real scope control, and the ownership gate only skips accounts swapped or imported since start. Effect on other hosts: not observed; unproven (a refresh may rotate the refresh token).
- One attempt per poll. A failure (non-200, transport error, bad reply) shows `unauthorized`, keeps the last numbers and waits out the normal 1 h unauthorized backoff. No retry loop. Response bodies and tokens are never logged.

## Provisional client id
`usage.DefaultClientID` is provisional, pending confirmation. If the endpoint rejects it every refresh fails as `unauthorized` and nothing is stored.

## First live test
Use the throwaway account `anewdevteam`, with Matthew present. Do not point it at a real account first.
1. Store the throwaway login, make sure no host holds it, start the server with `--refresh-tokens --refresh-accounts <its id>`.
2. Let the token expire (or wait for a 401), then press Refresh on its card.
3. Expect: the card shows usage, the Account's stored login has a new `expiresAt` (check key names and sizes only, never print a token), and the vault holds `vault.bin.bak`.
4. A `poll failed ... reason=unauthorized` log line carries `body_class`: `token_expired`, `token_revoked`, `invalid_credentials`, `permission`, `other`, `no_body` or `unparseable`. It is a class chosen by the server from assumed error-body wording (unverified against the live endpoint); the body itself is never logged.
5. Every refresh attempt logs one line: `action=refresh result=ok account=<label>` (only after the vault write succeeded) or `action=refresh result=failed account=<label> status_class=<class>`, where `status_class` is chosen by the server from the token call's HTTP status: `bad_request` (400), `unauthorized` (401), `forbidden` (403), `rate_limited` (429), `server_error` (5xx), `network` (transport error or timeout), `other`. No body text, token or identity is logged. A failed vault write logs `result=failed` without `status_class` and never `result=ok`.
6. If it shows `unauthorized`, check the server log for `action=refresh`. Stop the flag and fall back to Sign in again.
