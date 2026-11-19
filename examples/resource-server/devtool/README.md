# devtool

Creates the testdata the resource-server examples need on a local Passflow, and issues real tokens
through its public HTTP API. Nothing here signs a token by hand. It is for a local server only.

Run it from this directory, with a local Passflow server running:

```sh
go run . seed
go run . tokens
go run . totp <secret>
```

| Command | What it does |
|---|---|
| `seed` | Creates app A (origin `http://localhost:5173`) and app B, both `Offline`, with PKCE on and the 2FA policy `disabled`. Registers one password user on app A and enrols TOTP through `/user/2fa/setup/*`. Prints the app IDs, the user, the TOTP secret and its settings, and writes them to `seed.json`. Each run makes new apps and a new user. |
| `tokens` | Signs in on app A (`aal1.jwt`, `aal1.refresh`), upgrades that session with TOTP on `/auth/refresh` (`aal2.jwt`), and signs in on app B (`wrong-aud.jwt`). Writes the `tokens.json` manifest and prints `T0`, the `auth_time` of `aal2.jwt`. |
| `totp [--algorithm SHA1] [--digits 6] [--period 30] <secret>` | Waits for the next TOTP period and prints its code for a TOTP secret. The flags come before the secret. |

The TOTP settings are the ones the server enrolled the secret with. `seed` reads them from the
answer of `/user/2fa/setup/begin`: `totp_digits` and `totp_period`, and the `algorithm`, `digits`
and `period` of the `otpauth://` URI in `qr_code_url`. It falls back to the RFC 6238 defaults,
HMAC-SHA1, 6 digits and 30 seconds, only for a value the answer leaves out. They follow the app's
2FA settings, and a server in FIPS mode enrols with SHA-256 where the app says SHA-1. `seed.json`
keeps them as `totp_algorithm`, `totp_digits` and `totp_period`, and `tokens` uses them. `totp`
takes them as flags, with the RFC 6238 defaults; pass the values from `seed.json` for an app with
other settings. Devtool computes SHA-1, SHA-256 and SHA-512 codes of 6 to 8 digits.

Passflow accepts each TOTP code once, so `tokens` and `totp` never send the code of the current
period, which enrolment or an earlier command may have used. Each waits for the next period to
begin, up to one period, and uses that period's code.

Every sign-in sends the scopes `offline` and `id`. Passflow issues a refresh token and a `sid` only
when `offline` is requested and the app is `Offline`, and an upgrade needs both.

Every registration and sign-in uses PKCE, as a browser app does. Devtool creates a random
`verifier`, sends its S256 hash as `code_challenge` to `/auth/register` or `/auth/login`, and trades
the one-time `code` from the answer, with the `verifier`, for the tokens on `/auth/pkce_exchange`.
An app with PKCE off returns the tokens at once, and devtool uses them.

`tokens.json` is an array with one entry per token: `{file, app, acr, auth_time, exp}`.

## Flags

| Flag | Default | Commands | Meaning |
|---|---|---|---|
| `--server` | `http://localhost:8765` | `seed`, `tokens` | The Passflow base URL |
| `--key` | `test-management-key` | `seed` | The management key from `passflow.yaml` |
| `--out` | `.out` | `seed`, `tokens` | Where the files go. Git ignores the default, because they hold credentials. |
| `--algorithm` | `SHA1` | `totp` | The HMAC hash: `SHA1`, `SHA256` or `SHA512` |
| `--digits` | `6` | `totp` | The code length, 6 to 8 |
| `--period` | `30` | `totp` | Seconds per code |

`scripts/api-check.sh` reads the tokens from that directory:

```sh
../scripts/api-check.sh --tokens .out
```
