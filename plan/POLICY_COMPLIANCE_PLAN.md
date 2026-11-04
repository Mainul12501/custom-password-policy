# Plan: Close Compliance Gaps with RHBL-CO-IT-POL-001

Source: Software Password Architecture Policy (`password_policy.pdf` / `password_policy.md`), Rev 01, effective 01/11/2026.
Package: `Mainul\PasswordPolicy` (Laravel 10–13, PHP ^8.2).

## 1. Current state

Implemented today:

| Clause | Feature | Where |
|---|---|---|
| 3.5.1 (part) | Max password age, redirect/403 when expired | `PasswordExpiryService`, `PasswordExpiryMiddleware` |
| 3.5.3 | Password history, no reuse of last N | `PasswordHistoryService`, `PasswordNotReusedRule`, `HasPasswordPolicy` |
| (PCP/01) | Complexity rule | `PasswordPolicyRule` |

Everything else in section 3 is missing or delegated to Laravel (see section 4 for the full map).

## 2. Decisions already made

1. **SMS delivery** goes through `xenon/laravelbdsms`. It is an optional dependency (`suggest`, not `require`). The package defines a `PasswordSmsChannel` contract and a default implementation that calls it. If the package is not installed, SMS delivery is disabled and a clear exception is thrown when a phone-only user is processed.
2. **TLS/HTTPS enforcement (3.3.1)** is active only when `app()->environment('production')` is true. In other environments the middleware is a no-op. It stays overridable through config (`tls.enforce` = `null` means auto by environment, `true`/`false` forces).

## 3. Open assumptions (change if wrong)

- The host `User` model uses `HasPasswordPolicy` and has `email` and `phone` columns (column names configurable).
- "Disabled account" is represented by a nullable `disabled_at` column, which the package adds.
- Roles are read from a configurable callback or attribute. The package does not own the role system (needed for 3.6.6 and 3.9).
- MFA: the package provides the enforcement hook and a driver contract. It ships a TOTP driver as a later phase and does not reimplement an auth UI.
- The package supports both web (session) and API (Sanctum/Passport token) apps for session and token termination.

## 4. Gap map (clause → work item)

| Clause | Work item | Phase |
|---|---|---|
| 3.1.2 | Temporary password generator | 1 |
| 3.1.3, 3.1.4 | Secure delivery (mail, then SMS) | 1 |
| 3.1.5, 3.1.6 | Force change at first login | 1 |
| 3.2.1–3.2.4 | Hash/mask guard: `Hash` driver check, `$hidden` check, log scrubber | 2 |
| 3.3.1, 3.3.2 | Production-only HTTPS middleware, reject passwords in query string | 2 |
| 3.5.4 | Current-password confirmation rule | 1 |
| 3.5.2, 3.8.4 | Session and token termination service | 3 |
| 3.7.1, 3.7.2, 3.7.3 | Audit log (table, model, policy gate, redaction) | 2 |
| 3.4.1, 3.4.2 | Tiered lockout and IP-burst permanent lockout | 3 |
| 3.5.1 (part 2), 3.8.3 | Auto-disable at expiry + 1 day, manual disable | 3 |
| 3.6.3–3.6.5 | Reset-link expiry config check, reset notification | 4 |
| 3.6.6 | Block self-service reset for low-clearance roles | 4 |
| 3.7.4 | Unusual-login detection and alert event | 4 |
| 3.7.5 | Compromise response (force reset + kill sessions) | 3 |
| 3.4.3, 3.4.4, 3.9.2 | MFA enforcement hook and driver contract | 5 |
| 3.9.1, 3.9.2 | Admin-specific password rules, admin account separation guard | 5 |
| 3.9.3, 3.9.4 | Service-account registry (owner, purpose, rotation due date) | 5 |
| 3.9.5 | Default-password detector command | 5 |
| 3.8.5 | Leaver command: disable + kill sessions + flag shared passwords | 5 |

Out of scope (process or infrastructure, not package code): 3.1.1, 3.2.5, 3.2.6, 3.8.1, 3.8.2, form FRM-001. The README will list these as "host responsibility".

## 5. Phases

### Phase 1: Account lifecycle basics (3.1.x, 3.5.4)

**Migration** `add_policy_columns_to_users_table`:
- `must_change_password` boolean default false
- `disabled_at` nullable timestamp
- `disabled_reason` nullable string
- `locked_until` nullable timestamp, `failed_login_count` unsigned int default 0, `lockout_level` tinyint default 0 (used in phase 3, added now to avoid a second migration on `users`)

**New classes**
- `Services/TemporaryPasswordService`: `generate(): string` using `random_int` and a CSPRNG over a configurable alphabet, min 12 chars, guaranteed to satisfy `PasswordPolicyRule`, rejects predictable patterns (sequential, repeated, contains the user's name or email local-part). `issueFor($user, channel)` sets the hashed password, `must_change_password = true`, and sends it.
- `Contracts/PasswordDeliveryChannel` with `send($user, string $temporaryPassword): void`.
  - `Delivery/MailChannel`: uses `Mail`, the user's company email. Mailable never logs the password.
  - `Delivery/SmsChannel`: uses `xenon/laravelbdsms` if installed, sends to the registered phone.
  - `Services/DeliveryResolver`: email first, falls back to phone only when the user has no company email (3.1.3). If neither exists, throws `NoSecureChannelException`. No plain-text fallback.
- `Http/Middleware/ForcePasswordChangeMiddleware` (alias `password.force_change`): blocks everything except the change/logout routes while `must_change_password` is true. Same exclusion config as the expiry middleware. JSON requests get 403 `password_change_required`.
- `Rules/CurrentPasswordRule`: 3.5.4. Passes only if the value matches the user's current password. It is skipped when the change is forced (`must_change_password`) or admin-initiated (explicit flag).
- `HasPasswordPolicy` additions: when the password changes, set `must_change_password = false` unless the change was flagged as temporary. A temporary password reused as the new password is rejected by history (3.1.6).

**Config** `temporary_password` (length, alphabet, delivery order, sms enabled) and `force_change` (excluded routes).

**Tests**: generator strength and uniqueness, delivery fallback order, no-channel failure, middleware block/allow, the temp password can't become permanent, current-password rule.

### Phase 2: Audit log, redaction, transport (3.2.x, 3.3.x, 3.7.1–3.7.3)

**Migration** `create_password_audit_logs_table`: `id`, `user_id` nullable, `identifier` (the attempted email or username), `event` (string), `outcome` (`success`/`failure`/`blocked`), `ip_address`, `user_agent`, `context` json, `created_at`. Indexes on (`user_id`, `created_at`), (`ip_address`, `created_at`), `event`.

**Events logged** (via a single `Services/AuditLogger`): `login_attempt`, `login_success`, `login_failed`, `lockout`, `password_changed`, `password_reset_requested`, `password_reset_completed`, `temp_password_issued`, `forced_reset`, `sessions_terminated`, `account_disabled`.

**Wiring**: listeners on Laravel's `Login`, `Failed`, `Lockout`, `PasswordReset`, `Attempting`; the trait's `updating` hook for `password_changed_at`.

**Redaction (3.7.2)**: `Support/Redactor` strips `password`, `password_confirmation`, `current_password`, `token`, `temporary_password`, `code` from any context array before it is stored. A Monolog processor, registered by the provider (opt-in via `logging.redact`), applies the same redaction to application and error logs.

**Access control (3.7.3)**: `Gate::define('view-password-audit-logs')`, resolved from a config callback or ability name. Default deny. The model has no public route. An Artisan command `password-policy:audit` provides read access, and the gate is checked in any host-built UI.

**Transport (3.3)**: `Http/Middleware/EnforceSecureTransport` (alias `password.secure`).
- Active only if `config('password-policy.tls.enforce')` is `true`, or is `null` and `app()->environment('production')`.
- Non-HTTPS request: 403 for JSON, redirect to `https://` for GET web requests, 403 otherwise. Honours trusted proxies (`$request->isSecure()`).
- Always (when active): rejects requests where password-like keys appear in the query string (3.3.2).
- Not active in `local`, `testing`, etc.

**Storage guard (3.2.1–3.2.4)**: a boot-time check (production only, warning not exception) that `hashing.driver` is `bcrypt` or `argon`/`argon2id`, and that the user model hides `password`. `password-policy:check` Artisan command reports both.

**Tests**: each event is recorded with correct outcome, secrets never reach `context`, gate denies by default, TLS middleware matrix (production vs local vs override), query-string rejection.

### Phase 3: Lockout, disable, session termination (3.4.1–3.4.2, 3.5.1b, 3.5.2, 3.7.5, 3.8.3–3.8.4)

**Lockout service** `Services/LockoutService`, driven by the audit/user columns. It is not Laravel's `ThrottlesLogins`, because the policy needs persistent, tiered locks.

| Cycle | Trigger | Lock |
|---|---|---|
| 1 | 5 consecutive failures | 5 min |
| 2 | 5 more after cycle 1 | 10 min |
| 3 | 5 more after cycle 2 | 30 min |
| 4+ | continued failures | extended lock (config, default 2 h) **and** `requires_identity_verification = true` |
| IP burst | N failures from one IP within 60 s against an account (config, default 5) | permanent lock (`locked_until = null`, `is_permanently_locked = true`), admin unlock only |

- A successful login resets `failed_login_count`. `lockout_level` resets after a configurable quiet period (default 24 h).
- Extended lock and identity verification: an unlock requires `LockoutService::unlock($user, verifiedBy: $admin)`. This is a service method, with no UI shipped.
- `Http/Middleware/EnsureAccountNotLocked` and a `LoginGuard` helper that the host's login action calls before checking credentials, so locked accounts get no credential oracle (same generic message).
- Listeners increment counters on `Failed`, and reset on `Login`.
- Migration additions: `is_permanently_locked`, `requires_identity_verification`.

**Auto-disable (3.5.1)**: `Console/DisableExpiredAccountsCommand` (`password-policy:disable-expired`, scheduled daily by the provider when enabled). Disables users whose password is older than `expiry.days + expiry.grace_days` (grace default 1). Sets `disabled_at`, reason `password_expired`, logs the event and terminates sessions. Also checked at login by the middleware so a user is blocked immediately and not only at the next command run. `Middleware/EnsureAccountEnabled` returns 403 `account_disabled`. Re-enabling is an explicit admin call, `AccountService::enable()`, which also sets `must_change_password`.

**Session and token termination** `Services/SessionTerminator`:
- Database session driver: deletes the user's rows from `sessions`.
- Other drivers: rotates `remember_token` and bumps a `session_version` column that `EnsureSessionVersion` middleware compares, so existing sessions on any driver become invalid.
- Sanctum: deletes `tokens()` if the user has `HasApiTokens`. Passport: revokes tokens if available.
- Called automatically after a password change or reset (3.5.2), disable, and compromise response.

**Compromise response (3.7.5)**: `AccountService::markCompromised($user, $actor)`: sets `must_change_password`, rotates the password hash to an unusable random value, terminates all sessions, logs `forced_reset`, fires `PasswordCompromised` event.

**Tests**: lockout ladder timings (with `Carbon::setTestNow`), IP-burst permanent lock, reset on success, disable-after-grace boundary, session termination per driver, compromise flow.

### Phase 4: Reset flow and monitoring (3.6.x, 3.7.4)

- **Reset-link hardening (3.6.3, 3.6.4)**: Laravel's broker already issues single-use, expiring tokens. The package adds a `password-policy:check` assertion that `auth.passwords.*.expire` is at or below a configured maximum (default 60 min), and a test guard that no password is ever emailed. No new reset UI is written.
- **Reset notification (3.6.5)**: listener on `PasswordReset` sends `PasswordWasResetNotification` (mail, plus SMS when no email), containing time, IP and a "report this" instruction. Never includes the password.
- **Identity verification (3.6.2)**: the Laravel broker verifies via the emailed token. For SMS-only users, a `ResetIdentityVerifier` contract (default: delivers a one-time code through the SMS channel, hashed at rest, single-use, short TTL).
- **Low-clearance block (3.6.6)**: `Rules/CanSelfResetPassword` and `Middleware/BlockSelfReset`. The `restricted_roles` config (default `['BA', 'SO']`) is matched via a `role_resolver` callback. Blocked users get a message to contact the admin, and the attempt is logged as `blocked`.
- **Unusual login (3.7.4)**: `Services/AnomalyDetector` with two checks: repeated failures (reuses audit data) and atypical location (new IP /24, or a country change if the host supplies a `GeoResolver`). Dispatches `UnusualLoginDetected`, with a default mail alert to configured recipients. A `known_logins` table stores per-user hashed IP prefixes. No external geo service is required.

**Tests**: notification content has no secrets, restricted roles blocked, anomaly thresholds, reset code single-use and expiry.

### Phase 5: MFA, admin and service accounts, leavers (3.4.3–3.4.4, 3.8.5, 3.9.x)

- **MFA hook**: `Contracts/MfaDriver` (`isEnrolled`, `challenge`, `verify`). `Middleware/RequireMfa` enforces it per policy:
  - Mandatory for admin accounts, remote and externally exposed accounts (3.4.3, 3.9.2) via `mfa.required_for` callbacks (`is_admin`, `is_remote`).
  - Supported (enrollable) for standard users (3.4.4), enforcement optional through config.
  - A TOTP driver using `pragmarx/google2fa` is optional and `suggest`ed. The package ships the contract, the middleware and the config, and the host provides UI.
- **Admin separation and strength (3.9.1, 3.9.2)**: config `admin` block with stricter complexity (default min 14), shorter expiry, and a larger history count. `PasswordPolicyRule` accepts a profile (`PasswordPolicyRule::for($user)`). `password-policy:check` warns when an admin's email domain matches the daily-work domain list (config), which is the best the package can do for "architecturally separate".
- **Service accounts (3.9.3, 3.9.4)**: `service_accounts` table (`user_id`, `owner`, `purpose`, `rotation_days`, `last_rotated_at`, `next_rotation_at`). The model refuses to save without owner and purpose. `password-policy:rotation-due` command lists and notifies overdue accounts, and a `ServiceAccountService::rotate()` method hands the new secret to a host-provided vault callback and never stores it. Service accounts are excluded from interactive-login rules, and expiry is replaced by rotation schedule.
- **Default passwords (3.9.5)**: `password-policy:check-defaults` hashes a configurable list of known defaults (`password`, `admin123`, vendor defaults) and checks every user, flagging matches as `must_change_password`. Intended as a pre-go-live gate, and is also runnable in CI.
- **Leaver flow (3.8.3, 3.8.5)**: `password-policy:offboard {user}` disables the account, terminates sessions and tokens, logs the event, and lists service and shared accounts (`shared_with` config callback) whose passwords must be rotated, creating rotation-due entries for them.

**Tests**: MFA gating matrix, admin profile applied, service-account validation, default-password detection, offboard end to end.

### Phase 6: Docs and release

- README: install, config reference, host responsibilities and out-of-scope clauses, a clause-by-clause compliance table.
- `password-policy:check` becomes the single compliance self-test (config, hashing driver, hidden attributes, TLS in production, reset expiry, MFA wiring).
- CHANGELOG, tag **v0.2.0**. The new `users` columns are added by new migrations, so existing installs upgrade without editing old ones.

## 6. Cross-cutting rules

- Every new feature is behind a config switch with a policy-compliant default (on). Config keys stay grouped like the current file.
- No password, temporary password, reset code or token is ever written to logs, audit context, notifications or exception messages (enforced by `Redactor` tests).
- Backwards compatible: existing middleware aliases and the `password_policy` validator keep working.
- New migrations only, no edits to the two existing ones.
- Each phase ships with PHPUnit tests (Testbench) and leaves the suite green before the next starts.

## 7. Suggested order and size

| Phase | Scope | Rough size |
|---|---|---|
| 1 | Temp password, delivery (mail+SMS), forced change, current-password | Medium |
| 2 | Audit log, redaction, TLS (production only), storage guard | Medium |
| 3 | Lockout, auto-disable, session termination, compromise | Large |
| 4 | Reset notification, role block, anomaly alerts | Medium |
| 5 | MFA, admin/service accounts, defaults, offboarding | Large |
| 6 | Docs, `check` command, release | Small |

Start with Phases 1 and 2, because Phase 3 onwards depends on the audit log and the new `users` columns.

## 8. Risks

- **Lockout as a DoS vector**: an attacker can lock out users on purpose. The IP-burst permanent lock makes this worse. Mitigation is the configurable thresholds and that admin unlock is audited. Needs product sign-off on the permanent-lock rule.
- **Policy ambiguity in 3.4.2**: "second occurrence after the same lockout cycle" and "extended temporary lockout" are not numerically defined. The defaults in Phase 3 are my interpretation and should be confirmed with IT Security.
- **Auto-disable plus expiry**: users with `password_changed_at = null` currently count as expired, so enabling auto-disable could disable every existing user on upgrade. The upgrade migration backfills `password_changed_at = now()` for existing users where null.
- **SMS dependency**: `xenon/laravelbdsms` is configured per gateway in the host app. The package must not assume a particular gateway, and its API should be verified against the installed version before Phase 1 coding.
- **MFA scope**: the package can only enforce and hook MFA. Enrollment UI and the secret storage belong to the host.

## 9. Progress

**Phases 1 and 2 implemented** (93 tests passing). Deviations from the plan above:

- `password_reset_requested` is not logged: Laravel fires no event for it. Reset *completion* is logged. Revisit in Phase 4 by hooking the broker.
- Login attempts are logged on the `Login` (success), `Failed` (failure) and `Lockout` (blocked) events. `Attempting` is skipped because its outcome is unknown.
- Log redaction is a Monolog tap (`Logging\RedactSensitiveData`) that each host adds to its channel config, not an automatic registration.
- The storage guard is the `password-policy:check` command only. No boot-time warning, to avoid per-request log noise.
- `must_change_password` and the lockout columns come from one new migration (`..._000003`), which also backfills `password_changed_at` for existing users.
- Hosts need `HasPasswordPolicy` on the user model for `issueFor()` (it calls `setTemporaryPassword()`).
- `xenon/laravelbdsms` facade `SMS::shoot($mobile, $text)` was checked against v2.0.5.0 source. The return value is not inspected, so only exceptions count as failure.
- `tests/TestCase.php` no longer uses `RefreshDatabase`: with Testbench 11 it ran the package migrations before the `users` table existed (all 46 original tests errored).

**Phase 3 implemented** (145 tests passing). Deviations and decisions:

- `EnsureAccountNotLocked` and `EnsureAccountEnabled` are one middleware, `password.account_active` (`EnsureAccountActive`), which also disables an account on the spot once the grace period is over. `password.session_version` is the separate session check.
- `LoginGuard::ensureCanAttempt($identifier)` is what the host's login action must call before checking credentials. A locked or disabled account gets one generic message. Anything else cannot be enforced by a package, because Laravel's `Failed`/`Login` events cannot veto a login.
- The IP-burst counter lives in the cache (60 s TTL), not the audit log, so it works when auditing is off. The cache store must be shared across servers (not `array`/`file` on multi-server setups).
- Added `last_failed_login_at` (quiet-period reset) alongside `is_permanently_locked`, `requires_identity_verification`, `session_version`.
- Interpretation of 3.4.2 (still to confirm with IT Security): cycles 1-3 lock 5/10/30 minutes; cycle 4+ locks 120 minutes and needs `LockoutService::unlock($user, $verifiedBy)`; failures made while locked do not count; cycle counter resets after 24 h quiet.
- **Default IP burst is 5 failures in 60 s, equal to `max_attempts`.** A person mistyping 5 times in a minute is permanently locked, and cycle 1 is only reachable by slower attempts. Raise `lockout.ip_burst.attempts` if that is too harsh.
- A password change ends the user's other sessions and tokens but keeps the session that made the change. A session with no stored version (created before `password.session_version` was deployed) adopts the current one on first request.
- Users with a null `password_changed_at` are never auto-disabled.
- Sanctum/Passport tokens are removed via `tokens()->delete()`; this is covered by code path only, not by a test, because neither package is installed in the test suite.

**Phase 4 implemented** (189 tests passing). Deviations and decisions:

- `PasswordDeliveryChannel` gained `sendText($user, $text, $subject)`, used for reset codes and the reset notice. Custom channels must implement it.
- Reset links (3.6.3, 3.6.4): Laravel's broker already issues single-use, expiring links and never emails a password. The package only verifies it: `password-policy:check` fails if any `auth.passwords.*.expire` exceeds `reset.max_expire_minutes` (60). No new reset UI.
- Reset identity (3.6.2): `ResetIdentityVerifier` contract, default `ResetCodeVerifier` (hashed one-time code, 10 min TTL, single use, locks after 5 wrong guesses, sent by email or SMS). The host decides where in its reset flow to call `issue()`/`verify()`.
- Reset notice (3.6.5) is sent synchronously. A delivery problem is audited and reported and never undoes the reset.
- `password_reset_requested` is audited from Laravel's `PasswordResetLinkSent` event where the framework version fires it.
- Self-reset block (3.6.6): `password.block_self_reset` middleware and `CanSelfResetPassword` rule. Roles come from `reset.role_attribute` or an invokable `reset.role_resolver`. **A blocked response tells the caller the account exists and has a restricted role** (the policy requires telling those users to contact the admin); unknown emails pass through to the normal generic answer.
- Unusual logins (3.7.4): repeated failures (default 3 in 10 min, alert once per window, counted in the cache, also for unknown accounts) and first login from a new /24 (IPv6 /48) network or, with an optional `GeoResolver`, a new country. Only a keyed hash of the prefix is stored. The first login only sets the baseline. Alerts go to the audit log (`outcome=alert`), the `UnusualLoginDetected` event, and an email to `anomaly.alert_recipients` if set.
- Like the burst counter, the failure counter needs a shared cache store on multi-server setups.
- Mailpath tests use Laravel's `array` mailer because `Mail::fake()` ignores `Mail::raw()`.

**Phase 5 implemented** (240 tests passing). Deviations and decisions:

- MFA (3.4.3, 3.4.4, 3.9.2): the package ships the contract (`MfaDriver`), `MfaService` and the `password.mfa` middleware only. **No TOTP driver is bundled**, so nothing can actually be enrolled until the host supplies a driver. Admins always need MFA; remote and everyone-mode are config switches. With no driver configured, users who need MFA are blocked (fail closed). A new login clears the verified flag. "Remote" is only evaluated when `mfa.internal_networks` is filled in; an empty list means "cannot tell" and is not treated as remote.
- Admin accounts (3.9.2): `admin.roles` / `admin.flag_attribute` (roles come from the same source as `reset.role_attribute` / `reset.role_resolver`). Stricter rules are applied with `PasswordPolicyRule::for($user)`; the bare `password_policy` validator alias has no user and keeps the global rules. Admin overrides can only tighten (longer minimum, shorter expiry, longer history). **The defaults (min length 14, expiry 60 days, history 5) are my assumption; the policy only says "stronger".**
- Admin separation (3.9.1) is a check, not enforcement: `password-policy:check` fails when an admin's login email is on `admin.daily_email_domains` (warns while that list is empty).
- Service accounts (3.9.3, 3.9.4): `service_accounts` table, owner and purpose mandatory, rotation schedule replaces password expiry and auto-disable. Rotation needs a host `vault` callable, is refused without one, and rolls back if the vault fails. The secret is never stored, returned or logged. `password-policy:rotation-due [--notify] [--rotate]`. Scheduling `--rotate` is left to the host.
- Default passwords (3.9.5): `password-policy:check-defaults [--flag] [--user=]`, exits non-zero when any are found. It hashes each user against every default, so it is slow on big tables.
- Leavers (3.8.3, 3.8.5): `password-policy:offboard {id|email}` disables, ends sessions, and marks service accounts that list the leaver in `known_by` as due for rotation immediately. This replaces the planned `shared_with` config callback with data on the account itself.
- `PasswordExpiryService` constructor arguments are optional (resolved from the container), so code that instantiates it directly still works.

**Phase 6 implemented.** `README.md` (install, setup checklist, commands, caveats, clause-by-clause compliance table) and `CHANGELOG.md` (0.2.0) written. `password-policy:check` is the single self-test. **The v0.2.0 tag has not been created**: nothing is committed yet, and a tag needs a commit.
