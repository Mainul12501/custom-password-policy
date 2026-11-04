# Changelog

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
