# Signing in again (an account that shows "unauthorized")

Use it when an account's card says `unauthorized`: Anthropic refused the stored login (a 401, or an
expired refresh token). Waiting does not fix it, and Add Claude account refuses the same login as
`already stored`. **Sign in again** replaces the stored login for that same account.

## In the UI

The card shows `Anthropic refused the stored login` and a **Sign in again** button on its collapsed
face. Click it, pick the host that runs the sign-in, and press **Start sign-in**. The label is the
account's own and read-only. Then the same steps as Add Claude account: open Anthropic's link, sign in
as the same account, paste the code. The job runs through the usual add-account route
(`POST /api/accounts/add` with `{"host", "account"}`; status and code routes are unchanged).

## What it does

- The signed-in identity must equal the account's stored identity. A different account is refused
  with `that sign-in is a different account`, and nothing is stored.
- On a match it replaces only the `claudeAiOauth` block in `vault.bin`. ID, label and identity stay.
  The previous vault file is kept as `vault.bin.bak` (one deep, same passphrase).
- Ownership for the account goes back to the server copy (no holder, no write-back owed). The usage
  poller's failure count, 401 wait and error are cleared, and the account is polled next.
- No duplicate account is created, and no host's credentials file is read or written.

## While a host is signed in as that account

Allowed. That host's own login is a separate copy and is not touched, so it keeps running whatever it
has. The finished job says so (`A host is still signed in with the previous login...`). Swap the host
to the account afterwards if it should use the new login.

## Logs

Audit lines use `action=login_replace` with `host_id`, `account`, `result` and, on refusal, a
`reason` of `identity_mismatch`, `account_gone` or `store_refused`. No identity, token, code or
sign-in URL is logged.

## Troubleshooting

- `an add-account sign-in is already running`: one sign-in (of either kind) runs at a time. Finish or
  cancel it from the Account menu.
- `the account no longer exists`: it was removed while the sign-in waited. Add it again instead.
- Still `unauthorized` after a success: press **Refresh** on the card; a poll refused by the endpoint
  shows its own state.
