# mainul/password-policy

A Laravel package that implements the Remark HB **Software Password Architecture Policy**
(`RHBL-CO-IT-POL-001`, Rev 01): password rules, expiry and history, temporary passwords,
lockout, session termination, audit logging, MFA enforcement, and admin/service account controls.

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
       'current_password' => [new CurrentPasswordRule($user)],          // 3.5.4
       'password' => ['required', 'confirmed',
           PasswordPolicyRule::for($user),                              // admins get stricter rules
           new PasswordNotReusedRule($user)],                           // 3.5.3
   ]);
   ```

5. **Forgot-password form** (optional, 3.6.6): `'email' => [new CanSelfResetPassword()]`.

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

## What each part does

- **Password rules**: `PasswordPolicyRule` (length, upper, lower, number, special), `PasswordNotReusedRule`,
  `CurrentPasswordRule`. Admins get stricter values via `PasswordPolicyRule::for($user)`.
- **Temporary passwords**: `TemporaryPasswordService::issueFor($user)` generates a random password, delivers it
  by company email (SMS only when there is no usable email) and forces a change at first login.
  If no approved channel exists nothing changes. If delivery fails the change is rolled back.
- **Lockout**: 5 failures lock for 5, 10, then 30 minutes. Later cycles lock for 2 hours and need
  `LockoutService::unlock($user, $verifiedBy)`. 5 failures from one IP against one account within
  60 seconds lock it until an administrator unlocks it.
- **Expiry**: users are prompted at the expiry age and the account is disabled one day later.
- **Sessions**: `SessionTerminator` ends every session and API token of an account, on any session driver.
- **Audit log**: logins, password changes, resets, lockouts, disables, MFA, rotations and more, in
  `password_audit_logs`. Secrets are redacted before they are stored.
- **Monitoring**: repeated failures and logins from a new network raise a `UnusualLoginDetected` event, an audit
  entry and (optionally) an email.
- **MFA**: you supply the factor by implementing `Contracts\MfaDriver` and setting `mfa.driver`.
- **Service accounts**: register with `ServiceAccountService::register($user, $owner, $purpose)`. They rotate on a
  schedule and the new secret goes to your vault callback (`service_accounts.vault`).
- **Offboarding**: `php artisan password-policy:offboard {id|email}`.

## Commands

| Command | Purpose |
|---|---|
| `password-policy:check` | Self-test: hashing driver, hidden password, HTTPS in production, reset link expiry, MFA driver, admin separation, SMS dependency. Exits non-zero on a failure. |
| `password-policy:check-defaults [--flag] [--user=]` | Find accounts using a known default password (3.9.5). Slow on big user tables; run before go-live. |
| `password-policy:disable-expired [--dry-run]` | Disable accounts unchanged past expiry plus grace. |
| `password-policy:rotation-due [--notify] [--rotate]` | List, notify about, or rotate overdue service accounts. |
| `password-policy:offboard {user} [--actor=]` | Disable a leaver and flag the shared passwords they knew. |
| `password-policy:audit [--user= --event= --outcome= --limit=]` | Show recent audit entries (server access only). |

## Configuration

Everything lives in `config/password-policy.php` and is documented inline. The main groups:
`rules`, `expiry`, `history`, `lockout`, `temporary_password`, `reset`, `anomaly`, `tls`, `audit`,
`mfa`, `admin`, `service_accounts`, `defaults`, `sessions`, `columns`.

Production only: HTTPS enforcement (`tls.enforce = null`) is active only when `APP_ENV=production`.
Set it to `true` or `false` to force it.

## Things to know before relying on it

- **Shared cache**: the IP-burst counter and the repeated-failure counter use the cache. On more than one
  server use a shared store (Redis or database), not `array` or `file`.
- **Lockout wording**: policy clause 3.4.2 does not define "second occurrence" or "extended temporary lockout".
  The defaults are an interpretation and are configurable. With the default IP burst (5 in 60 s) a person who
  mistypes 5 times in a minute is locked until an administrator unlocks them. Raise
  `lockout.ip_burst.attempts` if that is too strict.
- **No bundled MFA factor**: until you provide an `MfaDriver`, users who need MFA are blocked.
- **Self-reset block**: the response for a restricted role (BA, SO) reveals that the account exists and has that
  role. Unknown emails get the normal answer.
- **Required columns**: the package migrations add `password_changed_at`, `must_change_password`, `disabled_at`,
  `disabled_reason`, `locked_until`, `failed_login_count`, `lockout_level`, `is_permanently_locked`,
  `requires_identity_verification`, `last_failed_login_at` and `session_version` to `users`. The table name
  `users` is fixed in the migrations. Users that already existed get `password_changed_at` set to the migration
  time so they are not expired immediately.
- **Delivery is synchronous**: temporary passwords, reset notices and alerts are sent inline, not queued.
- **Admin defaults are an assumption**: minimum length 14, expiry 60 days, history 5. The policy only says
  "stronger controls".

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
| 3.4.3 | MFA enforced for admin, remote, external | 🔌 | `password.mfa` + your `MfaDriver` |
| 3.4.4 | MFA available for standard users | 🔌 | `mfa.require_all` + your `MfaDriver` |
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
