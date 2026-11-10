# Verify a release before you run it

Use this before running anything downloaded from a GitHub release of `mbadali25/claude-utilities`. A release holds the server and agent archives, the agent installer scripts, `SHA256SUMS`, and `SHA256SUMS.sigstore.json`. Never edit a published release; a bad one is superseded by the next tag.

You need `cosign` (v2 or later) and `gh` (logged in; `gh attestation verify` needs a token). `<tag>` is the release tag, for example `v1.2.3`.

1. Download everything into an empty directory.

   ```
   mkdir release-check && cd release-check
   gh release download <tag> --repo mbadali25/claude-utilities
   ```

2. Check that `SHA256SUMS` was signed by this repo's release workflow on a real tag. The identity is anchored to the repo, the workflow file and a `vX.Y.Z` tag ref.

   ```
   cosign verify-blob \
     --bundle SHA256SUMS.sigstore.json \
     --certificate-identity-regexp '^https://github\.com/mbadali25/claude-utilities/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     SHA256SUMS
   ```

   Expected: `Verified OK`. A dry-run tag (`v0.0.0-rc.N`) signs with a different identity and does not match this regexp, by design.

3. Check each archive's provenance attestation. The attested files are the archives, not `SHA256SUMS`.

   ```
   gh attestation verify <archive> --repo mbadali25/claude-utilities --cert-identity-regex '^https://github\.com/mbadali25/claude-utilities/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
   ```

   Run it once per `.zip` and `.tar.gz`.

4. Check the files against the signed list.

   ```
   sha256sum -c SHA256SUMS
   ```

   Expected: every line `OK`. On Windows PowerShell, compare `(Get-FileHash <file>).Hash` with the line in `SHA256SUMS`.

## Weaker fallback

If neither `cosign` nor `gh` is present, the only check left is comparing one file's SHA-256 against a value you obtained over another channel (`CLAUDESWAP_SERVER_SHA256` in the server installer, once it exists). That proves the file matches the value you hold, not who built it. Use it only when you cannot install either tool, and say so in the ticket.

## Dry run (Matthew only)

The workflow can be exercised without a real release. Push a tag `v0.0.0-rc.N`: the workflow builds, creates a draft release, runs the same checks (steps 2 to 4 above, plus a count of four archives, before the draft is created) with the `v0\.0\.0-rc\.[0-9]+` identity, then deletes the draft. Delete the tag afterwards (`git push origin :v0.0.0-rc.N`). A failing run shows the identity mismatch or the cosign error in the `Verify before publishing` step. Tag protection and required review on `.github/workflows` are repo settings the supply-chain argument relies on; this workflow does not set them.
