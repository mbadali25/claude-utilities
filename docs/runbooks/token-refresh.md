# Server-side token refresh

`server --refresh-tokens` lets the server renew an expired stored login through the OAuth token endpoint instead of leaving the card at `unauthorized`. It is OFF by default.

## What it does
- On a 401 from the usage endpoint, POSTs JSON `{grant_type, refresh_token, client_id, scope}` to `https://platform.claude.com/v1/oauth/token` (30 s timeout, `Content-Type: application/json`, no other headers).
- Merges the answer into the stored `claudeAiOauth` block: new `accessToken`, new `refreshToken` if returned (else the old one stays), `expiresAt`, `refreshTokenExpiresAt` when given. `mcpOAuth`, `subscriptionType`, `rateLimitTier` and unknown fields are kept. The block is saved with `vault.ReplaceBlock` (a backup is kept).
- Refreshes only accounts no host holds (`ownership.OwnerOf(id).Server`). A held account is never refreshed by the server, as a conservative choice: a refresh may rotate the refresh token. That this signs a holding host out is unproven, not observed.
- One attempt per poll. A failure (non-200, transport error, bad reply) shows `unauthorized`, keeps the last numbers and waits out the normal 1 h unauthorized backoff. No retry loop. Response bodies and tokens are never logged.

## Provisional client id
`usage.DefaultClientID` is provisional, pending confirmation. If the endpoint rejects it every refresh fails as `unauthorized` and nothing is stored.

## First live test
Use the throwaway account `anewdevteam`, with Matthew present. Do not point it at a real account first.
1. Store the throwaway login, make sure no host holds it, start the server with `--refresh-tokens`.
2. Let the token expire (or wait for a 401), then press Refresh on its card.
3. Expect: the card shows usage, the Account's stored login has a new `expiresAt` (check key names and sizes only, never print a token), and the vault holds `vault.bin.bak`.
4. A `poll failed ... reason=unauthorized` log line carries `body_class`: `token_expired`, `token_revoked`, `invalid_credentials`, `permission`, `other`, `no_body` or `unparseable`. It is a class chosen by the server from assumed error-body wording (unverified against the live endpoint); the body itself is never logged.
5. Every refresh attempt logs one line: `action=refresh result=ok account=<label>` (only after the vault write succeeded) or `action=refresh result=failed account=<label> status_class=<class>`, where `status_class` is chosen by the server from the token call's HTTP status: `bad_request` (400), `unauthorized` (401), `forbidden` (403), `rate_limited` (429), `server_error` (5xx), `network` (transport error or timeout), `other`. No body text, token or identity is logged. A failed vault write logs `result=failed` without `status_class` and never `result=ok`.
6. If it shows `unauthorized`, check the server log for `action=refresh`. Stop the flag and fall back to Sign in again.
