# mainul/password-policy

A Laravel package for enforcing password and account security controls in Laravel applications.

## Features

- **Password rules**: configurable length, uppercase, lowercase, number and special-character requirements,
  personal-information checks, banned words and pattern detection. Administrators can use stricter rules.
- **Password history**: prevents users from reusing recent passwords and verifies the current password for
  voluntary changes.
- **Temporary passwords**: generates random passwords, delivers them through an approved email or SMS channel
  and requires a change at first login.
- **Account lockout**: supports tiered lockout periods, administrator unlocks and rapid-failure detection by IP.
- **Password expiry**: prompts users when passwords expire and can disable overdue accounts automatically.
- **Session termination**: ends an account's web sessions and API tokens after password changes, compromise or
  offboarding.
- **Audit logging and monitoring**: records security events, redacts secrets and detects unusual login activity.
- **Multi-factor authentication**: includes optional authenticator-app login and supports custom MFA drivers.
- **Password reset protection**: supports one-time identity-verification codes and role-based reset restrictions.
- **Service accounts**: tracks owners and purposes, schedules credential rotation and integrates with a vault
  callback.
- **Offboarding and security commands**: disables departing users, flags shared credentials and provides
  diagnostic, audit and maintenance commands.
- **JSON API**: every feature above is also available over HTTP for mobile apps, SPAs and other services.
  Uses Sanctum by default; Passport or any guard can be chosen in config or the database
  (see [JSON API](#json-api)).

Requires PHP 8.2+ and Laravel 10 to 13.

> This package provides the controls. Several of them only take effect once **you wire them into
> your application** (see [Setup](#setup)). The compliance table at the end says which.

## Install

```bash
composer require mainul/password-policy
php artisan vendor:publish --tag=password-policy-config
php artisan migrate        # the package loads its own migrations
php artisan password-policy:check
```

Optional: `composer require bacon/bacon-qr-code` to show a QR code on the authenticator-app set-up page.

Optional: `composer require xenon/laravelbdsms` to deliver temporary passwords and reset codes by SMS
when a user has no company email.

## Setup

1. **User model**: add the trait and hide the password.

   ```php
   use Mainul\PasswordPolicy\Traits\HasPasswordPolicy;

   class User extends Authenticatable
   {
       use HasPasswordPolicy;
       protected $hidden = ['password', 'remember_token'];
   }
   ```

   The trait records password history, stamps `password_changed_at`, ends the user's other sessions
   after a password change, and writes the audit entry.

2. **Routes**: add the middleware you need (all are aliased by the package).

   | Alias | Put it on | Policy |
   |---|---|---|
   | `password.expiry` | authenticated routes | 3.5.1 |
   | `password.force_change` | authenticated routes | 3.1.5 |
   | `password.account_active` | authenticated routes | 3.4.2, 3.5.1, 3.8.3 |
   | `password.session_version` | authenticated routes | 3.5.2, 3.8.4 |
   | `password.mfa` | authenticated routes | 3.4.3, 3.4.4, 3.9.2 |
   | `password.secure` | login, password and reset routes | 3.3 |
   | `password.block_self_reset` | forgot-password and reset-password routes | 3.6.6 |

   The routes named in `middleware.excluded_routes` (default `password.change`, `password.update`,
   `logout`) must stay reachable so users can actually change their password.

3. **Login action**: call the guard **before** checking credentials, so locked or disabled accounts
   get no chance to guess:

   ```php
   use Mainul\PasswordPolicy\Services\LoginGuard;
   use Mainul\PasswordPolicy\Exceptions\AccountLockedException;

   try {
       app(LoginGuard::class)->ensureCanAttempt($request->input('email'));
   } catch (AccountLockedException $e) {
       return back()->withErrors(['email' => $e->getMessage()]); // same message for every reason
   }
   ```

   Laravel's `Failed` and `Login` events feed the lockout counters automatically.

4. **Change-password form**: validate with the package rules.

   ```php
   use Mainul\PasswordPolicy\Rules\{PasswordPolicyRule, PasswordNotReusedRule, CurrentPasswordRule};

   $request->validate([
       // A rule object is skipped when the field is missing, so require it too.
       'current_password' => ['required', new CurrentPasswordRule($user)], // 3.5.4
       'password' => ['required', 'confirmed',
           PasswordPolicyRule::for($user),                              // admins get stricter rules
           new PasswordNotReusedRule($user)],                           // 3.5.3
   ]);
   ```

5. **Forgot-password form** (optional, 3.6.6): `'email' => [new CanSelfResetPassword()]`.

   **Reset identity check** (3.6.2, optional, useful for phone-only users): send and check a one-time code
   in your reset flow before accepting the new password.

   ```php
   $verifier = app(\Mainul\PasswordPolicy\Contracts\ResetIdentityVerifier::class);

   $verifier->issue($user);                          // code goes to company email, else phone
   if (! $verifier->verify($user, $request->code)) { // single use, 10 min, locks after 5 wrong tries
       abort(422, 'Invalid or expired code.');
   }
   ```

6. **Logs**: to keep secrets out of application logs (3.7.2), add the tap to your channel:

   ```php
   'single' => ['driver' => 'single', 'path' => storage_path('logs/laravel.log'),
       'tap' => [\Mainul\PasswordPolicy\Logging\RedactSensitiveData::class]],
   ```

7. **Audit log access (3.7.3)**: reading is denied to everyone until you define the gate:

   ```php
   Gate::define('view-password-audit-logs', fn ($user) => $user->isSecurityOfficer());
   ```

8. **Schedule**: `password-policy:disable-expired` is scheduled daily automatically. Schedule
   `password-policy:rotation-due --notify` (and `--rotate` if you want automatic rotation) yourself.

## Password Control Policy (PCP/01) defaults

The package ships with the following password-control defaults:

| Setting | Default | Policy |
|---|---|---|
| `rules.min_length` | 11 | At least 11 characters |
| `rules.require_*` | on | Upper, lower, number and special character |
| `expiry.days` | 30 | Change every 30 days |
| `history.max_reuse_count` | 5 | No reuse of the last five passwords |

Three more checks in `rules` cover the "don't" list. All are on by default:

- `forbid_personal_info`: rejects a password containing the user's name parts, the part of their email before the
  `@`, their phone number or their birthdate. It needs the user, so validate with `PasswordPolicyRule::for($user)`
  (without a user this check is skipped). The birthdate is read from `columns.birthdate` (default `date_of_birth`).
- `banned_words`: rejects passwords containing any listed word, ignoring case. Edit the list in the published
  config to include common weak passwords and any organization-specific terms.
- `forbid_patterns`: rejects four or more repeated characters (`aaaa`) and four or more sequential ones
  (`1234`, `abcd`, `dcba`).

Admins keep stricter values (14 characters, 60-day expiry): the stricter of the global and admin setting applies, so
with the 30-day default admins also change every 30 days.

Not enforceable in code: sharing or writing down passwords, reusing a password across systems, browser
"Remember Password", and keeping an admin password different from the same person's user-account password.

If you upgrade an existing app, the stricter defaults and checks apply to the next password change. Set the old
values in your published config to keep them.

## Authenticator app login (TOTP)

An optional second step: after the password, the user types the 6-digit code from Google Authenticator,
Microsoft Authenticator, Authy or any TOTP app. It is **off by default**. Once enabled it is required, and
users without an app are sent to a set-up page.

```bash
php artisan migrate                      # adds mfa_credentials and password_policy_settings
php artisan password-policy:totp --enable --scope=all --grace-days=7
```

Then either use the bundled pages or build your own on `TotpEnrollmentService`:

1. Set `totp.routes` to `true` in the published config. This adds `mfa/enroll`, `mfa/challenge` and
   `mfa/recovery-codes` (route names `mfa.enroll`, `mfa.enroll.confirm`, `mfa.challenge`, `mfa.verify`,
   `mfa.recovery`). Publish the views with `--tag=password-policy-views` to restyle them.
2. Put the `password.mfa` middleware on your authenticated routes. After a password login it redirects to the
   set-up page (no app yet) or the code page (app set up, code not yet entered).
3. Optional QR code: `composer require bacon/bacon-qr-code`. Without it the page shows the key to type in.

**Config or database?** `config/password-policy.php` (`totp` block) holds the defaults. The
`password_policy_settings` table holds runtime overrides for `totp.enabled`, `totp.scope`, `totp.grace_days`
and `totp.issuer`; the database wins. Change them with `password-policy:totp` or the API (`PUT admin/settings`) so the change is audited. To pin
the policy in code, set `totp.enabled` and `totp.lock_to_config` to `true`: the database can then not switch it
off. If the settings table is unreachable the config defaults are used.

- **Who**: `totp.scope` is `all`, `admins` or `remote` (outside `mfa.internal_networks`). Admins always need MFA.
- **Grace**: `totp.grace_days` lets users who have not enrolled sign in for that long after
  `password-policy:totp --enable`. Users who have enrolled are always challenged. Enabling through config
  alone records no start time, so there is no grace period.
- **Storage**: the secret is stored **encrypted** with `APP_KEY` (it cannot be hashed, the server must compute
  codes). Changing `APP_KEY` makes every stored secret unreadable, so users would need a reset. Recovery codes are
  stored as keyed hashes and shown once.
- **Protection**: a code can be used once (replay blocked), wrong codes count toward the normal lockout, and the
  session id is renewed after success. An enrolled app can not be replaced from a password-only session.
- **Lost phone**: the user enters a recovery code, or an administrator runs
  `password-policy:totp --reset={id|email}`; the user then sets up again at next login.
- A `mfa.driver` you configure yourself takes priority over the built-in driver.

## JSON API

Everything above is also available over HTTP, for mobile apps, SPAs and other services. It is **off by
default**: the routes exist but answer `404` until you switch it on, either in the published config
(`'api' => ['enabled' => true]`) or at runtime with no deploy:

```php
app(\Mainul\PasswordPolicy\Services\SettingsRepository::class)->set('api.enabled', true);
```

**Authentication.** The guard is `sanctum` by default (`composer require laravel/sanctum`). For Passport set
`api.guard` to the guard whose driver is `passport` (usually `api`); a list such as `['sanctum', 'api']` tries each
in turn. Set it in `config/password-policy.php` or in the database (`api.guard`, checked against
`config/auth.php`); the database wins. The guard is read on every request, so a change applies at once.

**Authorization.** The `/admin` endpoints are checked against Gate abilities that **deny everyone until you define
them** (`api.abilities`; the audit log uses `audit.gate_ability`):

```php
Gate::define('password-policy.manage-users', fn ($user) => $user->isSecurityOfficer());
Gate::define('password-policy.manage-service-accounts', fn ($user) => $user->isSecurityOfficer());
Gate::define('password-policy.manage-settings', fn ($user) => $user->isSecurityOfficer());
Gate::define('password-policy.view-compliance', fn ($user) => $user->isSecurityOfficer());
```

By default the `/admin` endpoints also sit behind `password.expiry`, `password.force_change` and `password.mfa`
(`api.admin_requires_mfa`, read when routes load). Admins therefore need an enrolled authenticator app first.

All paths are relative to `api.prefix` (default `/api/password-policy`). Errors are JSON:
`{"message": "...", "error": "code"}`, or Laravel's `{"errors": {...}}` for validation.

| Method and path | Who | Purpose |
|---|---|---|
| `POST login/check` | anyone, throttled | Is this account allowed to try a password? `423` if locked or disabled. Call before checking credentials. |
| `POST reset/code` | anyone, throttled | Send a one-time code to the user's company email or phone. Always `202`. |
| `POST reset/password` | anyone, throttled | `email`, `code`, `password`, `password_confirmation`. Checks the code, applies the policy, sets the password. |
| `GET policy` | signed in | The rules that apply to the caller (admins get stricter ones). |
| `GET password/status` | signed in | Expiry date, days left, forced-change flag, MFA state. |
| `POST password/validate` | signed in | Check a candidate password; changes nothing. |
| `PUT password` | signed in | `current_password`, `password`, `password_confirmation`. Ends the user's other sessions and tokens. |
| `GET mfa/status` | signed in | Whether MFA is on, required, enrolled, and verified for this token. |
| `POST mfa/enroll` | signed in | Start set-up: returns the key, the `otpauth://` URI and (with `bacon/bacon-qr-code`) an SVG. |
| `POST mfa/enroll/confirm` | signed in | `code` from the app. Returns the recovery codes once. |
| `POST mfa/verify` | signed in | `code` (or a recovery code). Marks **this token** as having passed MFA. |
| `POST mfa/recovery-codes` | signed in | `password`. New recovery codes; needs a verified token. |
| `GET admin/users/{id}` | users | Security state of an account. |
| `POST admin/users/{id}/unlock` | users | `verified_by` is required for permanent and identity-verification locks. |
| `POST admin/users/{id}/disable`, `.../enable` | users | `reason` optional. Enabling forces a password change. |
| `POST admin/users/{id}/compromise` | users | Make the password unusable and end every session (3.7.5). |
| `POST admin/users/{id}/temporary-password` | users | Send a new temporary password to the approved channel. It is never returned. |
| `POST admin/users/{id}/terminate-sessions` | users | End all sessions and API tokens. |
| `POST admin/users/{id}/offboard` | users | Disable a leaver and list the shared passwords to rotate. |
| `DELETE admin/users/{id}/mfa` | users | Wipe a user's authenticator app (lost device). |
| `POST admin/accounts/disable-expired` | users | `dry_run` optional. Disable accounts past expiry plus grace. |
| `GET admin/service-accounts[?due=1]` | service accounts | List. |
| `POST admin/service-accounts` | service accounts | `user_id`, `owner`, `purpose`, `rotation_days`, `known_by[]`. |
| `POST admin/service-accounts/{id}/rotate`, `.../rotate-due` | service accounts | Rotate through your vault. |
| `GET`, `PUT admin/settings`, `DELETE admin/settings/{key}` | settings | Database overrides: `totp.*`, `api.enabled`, `api.guard`. |
| `GET admin/audit` | audit gate | Filters: `user_id`, `event`, `outcome`, `from`, `to`, `per_page`. |
| `GET admin/compliance` | compliance | The `password-policy:check` self-test. |
| `POST admin/compliance/default-passwords`, `GET .../{scan_id}` | users | Default-password scan. With `user_id` it answers at once, otherwise it runs as a queued job. |

- **MFA for tokens.** API clients have no session, so a passed MFA code is remembered per bearer token in the cache
  for `mfa.token_ttl_minutes` (default 12 hours). Use a shared cache store on more than one server. Cookie-based
  SPA requests keep using the session.
- **Reset codes.** `reset/password` spends the code before it runs the checks that need the user (reuse, personal
  information), so those checks cannot be used to probe accounts. If one fails, the user asks for a new code.
- **Not exposed**: `password-policy:rotation-due --notify` (email) stays a console/scheduler job.

## Commands

| Command | Purpose |
|---|---|
| `password-policy:check` | Self-test: hashing driver, hidden password, HTTPS in production, reset link expiry, MFA driver, admin separation, SMS dependency. Exits non-zero on a failure. |
| `password-policy:check-defaults [--flag] [--user=]` | Find accounts using a known default password (3.9.5). Slow on big user tables; run before go-live. |
| `password-policy:disable-expired [--dry-run]` | Disable accounts unchanged past expiry plus grace. |
| `password-policy:rotation-due [--notify] [--rotate]` | List, notify about, or rotate overdue service accounts. |
| `password-policy:offboard {user} [--actor=]` | Disable a leaver and flag the shared passwords they knew. |
| `password-policy:totp [--enable] [--disable] [--status] [--scope=] [--grace-days=] [--reset=] [--actor=]` | Turn the authenticator-app login on or off, show its state, or wipe a user's app after a lost device. |
| `password-policy:audit [--user= --event= --outcome= --limit=]` | Show recent audit entries (server access only). |

## Configuration

Everything lives in `config/password-policy.php` and is documented inline. The main groups:
`rules`, `expiry`, `history`, `lockout`, `temporary_password`, `reset`, `anomaly`, `tls`, `audit`,
`mfa`, `totp`, `api`, `admin`, `service_accounts`, `defaults`, `sessions`, `columns`, `current_password`, `middleware`
(routes excluded from the expiry and forced-change checks) and `user_model`.

Production only: HTTPS enforcement (`tls.enforce = null`) is active only when `APP_ENV=production`.
Set it to `true` or `false` to force it.

## Things to know before relying on it

- **Shared cache**: the IP-burst counter and the repeated-failure counter use the cache. On more than one
  server use a shared store (Redis or database), not `array` or `file`.
- **Lockout wording**: policy clause 3.4.2 does not define "second occurrence" or "extended temporary lockout".
  The defaults are an interpretation and are configurable. With the default IP burst (5 in 60 s) a person who
  mistypes 5 times in a minute is locked until an administrator unlocks them. Raise
  `lockout.ip_burst.attempts` if that is too strict.
- **MFA factor**: until you enable the built-in authenticator app (`totp.enabled`) or provide an `MfaDriver`,
  users who need MFA are blocked.
- **Self-reset block**: the response for a restricted role (BA, SO) reveals that the account exists and has that
  role. Unknown emails get the normal answer.
- **Required columns**: the package migrations add `password_changed_at`, `must_change_password`, `disabled_at`,
  `disabled_reason`, `locked_until`, `failed_login_count`, `lockout_level`, `is_permanently_locked`,
  `requires_identity_verification`, `last_failed_login_at` and `session_version` to `users`. The table name
  `users` is fixed in the migrations. Users that already existed get `password_changed_at` set to the migration
  time so they are not expired immediately.
- **Delivery is synchronous**: temporary passwords, reset notices and alerts are sent inline, not queued.
- **Admin defaults are an assumption**: minimum length 14, expiry 60 days, history 5. The policy only says
  "stronger controls". The stricter of the global and admin value applies.

## Policy compliance

Legend: ✅ implemented by the package · 🔌 implemented, but needs your wiring or a host-supplied part ·
🅻 relies on Laravel itself, the package verifies or adds to it · ➖ outside what a package can do.

| Clause | Requirement | Status | Where |
|---|---|---|---|
| 3.1.1 | Identity verified via form FRM-001 | ➖ | Business process |
| 3.1.2 | Random, unpredictable temporary password | ✅ | `TemporaryPasswordService` |
| 3.1.3 | Secure channel: company email, else registered phone | 🔌 | Mail; SMS needs `xenon/laravelbdsms` |
| 3.1.4 | Never an unprotected channel | ✅ | No fallback; `NoSecureChannelException` |
| 3.1.5 | Forced change at first login | 🔌 | `password.force_change` middleware |
| 3.1.6 | Temporary password cannot stay permanent | ✅ | Trait + history |
| 3.2.1–3.2.3 | Hashed, salted, never plaintext | 🅻 | Laravel hashing; `password-policy:check` verifies the driver |
| 3.2.4 | Password masked everywhere | 🔌 | `$hidden` check, audit redaction, log tap |
| 3.2.5–3.2.6 | No hard-coded secrets, use a vault | ➖ | Developer practice |
| 3.3.1 | TLS only | 🔌 | `password.secure`, production only |
| 3.3.2 | No passwords in URLs/query strings | 🔌 | `password.secure` (query string; headers are not inspected) |
| 3.4.1 | Limit consecutive failures | 🔌 | `LockoutService` + `LoginGuard` |
| 3.4.2 | Tiered, extended and IP-burst lockout | 🔌 | `LockoutService` + `LoginGuard` |
| 3.4.3 | MFA enforced for admin, remote, external | 🔌 | `password.mfa` + the built-in authenticator app (`totp.enabled`) or your `MfaDriver` |
| 3.4.4 | MFA available for standard users | 🔌 | `mfa.require_all` or `totp.scope = all` + a driver |
| 3.5.1 | Max age, prompt, disable 1 day later | ✅ | Expiry middleware, `disable-expired`, `password.account_active` |
| 3.5.2 | Old password invalid after change | ✅ | Trait ends other sessions and tokens |
| 3.5.3 | Password history | ✅ | `PasswordNotReusedRule` |
| 3.5.4 | Current password for voluntary change | 🔌 | `CurrentPasswordRule` |
| 3.6.1 | Self-service reset | 🅻 | Laravel password broker |
| 3.6.2 | Independent identity check on reset | 🔌 | `ResetIdentityVerifier` (one-time code) |
| 3.6.3 | Short-lived, single-use links | 🅻 | Laravel broker; `password-policy:check` verifies expiry |
| 3.6.4 | Never email a password on reset | 🅻 | Laravel broker; notices never contain a password |
| 3.6.5 | Notify the user after a reset | ✅ | `NotifyPasswordReset` |
| 3.6.6 | BA/SO cannot self-reset | 🔌 | `password.block_self_reset`, `CanSelfResetPassword` |
| 3.7.1 | Log logins, changes, resets | ✅ | `AuditLogger` (reset *requests* only on Laravel versions that fire the event) |
| 3.7.2 | No secrets in logs | ✅ | Audit redaction; 🔌 log tap for application logs |
| 3.7.3 | Restricted log access | 🔌 | Gate denies until you define it |
| 3.7.4 | Unusual-login monitoring and alerts | ✅ | `AnomalyDetector` |
| 3.7.5 | Force reset, end all sessions on compromise | ✅ | `AccountService::markCompromised()` |
| 3.8.1–3.8.2 | Role-change forms and approvals | ➖ | Business process |
| 3.8.3 | Disable a leaver the same day | ✅ | `AccountService::disable()`, `password-policy:offboard` |
| 3.8.4 | Terminate sessions and tokens | 🔌 | `SessionTerminator` + `password.session_version` |
| 3.8.5 | Rotate passwords a leaver knew | ✅ | Offboarding marks service accounts due; rotation needs your vault |
| 3.9.1 | Admin accounts separate from daily accounts | 🔌 | Detected by `password-policy:check`, not enforced |
| 3.9.2 | Stronger admin passwords, MFA always | 🔌 | `PasswordPolicyRule::for($user)`; MFA needs a driver |
| 3.9.3 | Service accounts: owner and purpose | ✅ | `ServiceAccount` |
| 3.9.4 | Vaulted, rotating service passwords | 🔌 | Rotation here; the vault is yours |
| 3.9.5 | Change defaults before go-live | ✅ | `password-policy:check-defaults` |

## Testing

```bash
composer install
vendor/bin/phpunit
```

## License

MIT
