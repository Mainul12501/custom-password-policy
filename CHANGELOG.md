# Changelog

## Unreleased

### Added: automatic temporary password on user creation
- `temporary_password.auto_issue_on_create` (default `false`): `HasPasswordPolicy` issues and delivers a
  temporary password when a user is created. Override `shouldIssueTemporaryPassword()` to skip users. Delivery
  failures are reported/audited and never block the creation.

### Added: JSON API
- Every feature is now available over HTTP (`routes/api.php`, prefix `api/password-policy`): own password
  (policy, status, validate, change), authenticator app, pre-login lock check, one-time-code password reset,
  and administration (user unlock/disable/compromise/offboard/temporary password/sessions/MFA reset, service
  accounts, settings, audit log, compliance check, default-password scan, expired-account sweep).
- Auth guard defaults to `auth:sanctum`; Passport or any guard works through `api.guard`, which can be set in
  config or in the `password_policy_settings` table (`api.enabled` and `api.guard` are database-overridable).
- MFA "verified" state for token clients (no session): remembered per bearer token for `mfa.token_ttl_minutes`.
- `SessionTerminator` keeps the caller's own Sanctum/Passport token when a user changes their own password.
- `ExpiredAccountSweeper` and `DefaultPasswordScanner` services; the commands now use them.
- `LockoutService::lock()` (administrator lock), `ServiceAccountService::update()`, `remove()` and `notifyDue()`
  (`rotation-due --notify` now uses it). All three are available over the API.
- `mfa/challenge` and `mfa/verify` work with any `mfa.driver`, not only the built-in authenticator app.

Aligns the package with the Password Control Policy (PCP/01).

### Changed
- Defaults now match the policy: `rules.min_length` 11, `expiry.days` 30, `history.max_reuse_count` 5.

### Added
- `rules.forbid_personal_info`: rejects passwords containing the user's name, email name, phone number or birthdate (use `PasswordPolicyRule::for($user)`).
- `rules.banned_words`: rejects common words and the company name.
- `rules.forbid_patterns`: rejects repeated (`aaaa`) and sequential (`1234`, `abcd`) characters.
- `columns.birthdate` (default `date_of_birth`).
- Authenticator-app (TOTP) login: `Mfa\TotpDriver`, `TotpEnrollmentService`, bundled routes/views
  (`totp.routes`), recovery codes, replay protection and lockout on wrong codes. Off by default; once enabled it is
  required (`totp.scope`, `totp.grace_days`).
- `SettingsRepository` and the `password_policy_settings` table: database overrides over config defaults for
  `totp.enabled`, `scope`, `grace_days`, `issuer`. `totp.lock_to_config` pins the policy in code.
- `password-policy:totp` command (`--enable`, `--disable`, `--status`, `--scope`, `--grace-days`, `--reset`).
- `password-policy:check` reports how many users have not enrolled.
- Migrations `mfa_credentials` and `password_policy_settings`.

### Changed
- `MfaService::verify()` now renews the session id on success and counts failures toward the account lockout.

## 0.2.0

Implements the Remark HB Software Password Architecture Policy (RHBL-CO-IT-POL-001, Rev 01).

### Added
- **Temporary passwords**: generator, email then SMS delivery (`xenon/laravelbdsms`, optional), forced change at
  first login (`password.force_change`), `CurrentPasswordRule`.
- **Audit log** (`password_audit_logs`), secret redaction, a deny-by-default gate, `password-policy:audit`,
  and a Monolog tap for application logs.
- **Secure transport** middleware (`password.secure`), active in production only by default.
- **Lockout**: tiered lockout, extended lock with identity verification, permanent lock on IP bursts,
  `LockoutService`, `LoginGuard`.
- **Account lifecycle**: auto-disable one day after expiry (`password-policy:disable-expired`), `AccountService`
  (disable, enable, compromise response), `SessionTerminator`, `password.account_active`, `password.session_version`.
- **Reset flow**: reset notification, one-time reset codes (`ResetIdentityVerifier`), self-reset block for
  restricted roles, reset-link expiry check.
- **Monitoring**: unusual-login detection (`UnusualLoginDetected`).
- **MFA**: `MfaDriver` contract, `MfaService`, `password.mfa`.
- **Admin and service accounts**: stricter admin rules (`PasswordPolicyRule::for($user)`), service-account registry
  with vault-backed rotation, `password-policy:rotation-due`.
- **Go-live and leavers**: `password-policy:check-defaults`, `password-policy:offboard`.
- `password-policy:check` self-test command.
- Migrations: `users` policy columns, audit log, known logins, reset codes, service accounts.

### Changed
- Changing a password now ends the user's other sessions and API tokens (disable with
  `sessions.terminate_on_password_change`).
- `PasswordPolicyRule` accepts an optional user. `PasswordExpiryService` constructor arguments are optional.
- `PasswordDeliveryChannel` (new in this release) requires `send()` and `sendText()`.

### Upgrade notes
- Run `php artisan migrate`. Users that already exist get `password_changed_at` set to the migration time.
- Publish the config again (or merge the new sections) to see the new options. Defaults apply without it.
- Wire the middleware and the login guard as described in the README; the package cannot do it for you.

## 0.1.0
- Password complexity rule, expiry middleware, password history.
