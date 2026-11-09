# mainul/password-policy

**Language / ভাষা:** [English](#english-documentation) · [বাংলা](#বাংলা-ডকুমেন্টেশন)

<a id="english-documentation"></a>

## English Documentation

A Laravel package for enforcing password and account security controls: validation rules, expiry, history,
lockout, temporary passwords, MFA, audit logging, service accounts and a JSON API.

Requires **PHP 8.2+** and **Laravel 10 to 13**.

> The package supplies the controls. Several only take effect once **you wire them into your application**
> (middleware, login action, gates). Each section below shows exactly how, and the
> [compliance table](#policy-compliance) says which controls need wiring.

## Table of contents

1. [Features](#features)
2. [Installation](#installation)
3. [Quick start (10 minutes)](#quick-start)
4. [Feature guide](#feature-guide)
   - [1. Password rules](#1-password-rules)
   - [2. Password history (no reuse)](#2-password-history-no-reuse)
   - [3. Current-password confirmation](#3-current-password-confirmation)
   - [4. Password expiry](#4-password-expiry)
   - [5. Temporary passwords](#5-temporary-passwords)
   - [6. Account lockout](#6-account-lockout)
   - [7. Disable, enable and compromise](#7-disable-enable-and-compromise-accounts)
   - [8. Session termination](#8-session-termination)
   - [9. Password reset protection](#9-password-reset-protection)
   - [10. Authenticator-app MFA (TOTP)](#10-authenticator-app-mfa-totp)
   - [11. Custom MFA driver](#11-custom-mfa-driver)
   - [12. Admin accounts](#12-admin-accounts)
   - [13. Service accounts and rotation](#13-service-accounts-and-rotation)
   - [14. Offboarding leavers](#14-offboarding-leavers)
   - [15. Audit log](#15-audit-log)
   - [16. Unusual-login detection](#16-unusual-login-detection)
   - [17. Secure transport (HTTPS)](#17-secure-transport-https)
   - [18. Default-password scan](#18-default-password-scan)
5. [JSON API](#json-api)
6. [Artisan commands](#commands)
7. [Events](#events)
8. [Configuration reference](#configuration)
9. [Things to know before relying on it](#things-to-know-before-relying-on-it)
10. [Policy compliance](#policy-compliance)
11. [Testing](#testing) · [Upgrading](#upgrading) · [License](#license)

## Features

- **Password rules**: length, upper/lower case, number, special character, personal-information check,
  banned words and pattern detection. Admins get stricter rules.
- **Password history**: blocks reuse of recent passwords.
- **Temporary passwords**: random, delivered by approved email/SMS only, change forced at first login.
- **Account lockout**: tiered lock periods, administrator unlock, rapid-failure (IP burst) detection.
- **Password expiry**: prompts users and disables overdue accounts automatically.
- **Session termination**: ends web sessions and API tokens after a password change, compromise or offboarding.
- **Audit logging and monitoring**: records security events, redacts secrets, detects unusual logins.
- **Multi-factor authentication**: built-in authenticator app (TOTP) or your own driver.
- **Reset protection**: one-time identity codes and role-based reset restrictions.
- **Service accounts**: owner, purpose, scheduled rotation through your vault.
- **Offboarding and commands**: disable leavers, flag shared credentials, diagnostics.
- **JSON API**: everything above over HTTP for mobile apps and SPAs (Sanctum by default, Passport supported).

## Installation

```bash
composer require mainul/password-policy
php artisan vendor:publish --tag=password-policy-config
php artisan migrate        # the package loads its own migrations
php artisan password-policy:check
```

The service provider is auto-discovered. Optional extras:

| Package | Why |
|---|---|
| `bacon/bacon-qr-code` | Shows a QR code on the authenticator set-up page (otherwise the key is shown). |
| `xenon/laravelbdsms` | Delivers temporary passwords and reset codes by SMS when a user has no company email. |
| `laravel/sanctum` | Default guard for the JSON API. |
| `laravel/passport` | Alternative API guard. |

Publishable assets:

```bash
php artisan vendor:publish --tag=password-policy-config      # config/password-policy.php
php artisan vendor:publish --tag=password-policy-migrations  # copy migrations to edit them
php artisan vendor:publish --tag=password-policy-views       # restyle the MFA pages
```

**Database changes.** Migrations add these `users` columns: `password_changed_at`, `must_change_password`,
`disabled_at`, `disabled_reason`, `locked_until`, `failed_login_count`, `lockout_level`, `is_permanently_locked`,
`requires_identity_verification`, `last_failed_login_at`, `session_version`. They also create the tables
`password_histories`, `password_audit_logs`, `known_logins`, `password_reset_codes`, `service_accounts`,
`mfa_credentials` and `password_policy_settings`. The table name `users` is fixed. Existing users get
`password_changed_at` set to the migration time so they are not expired immediately.

## Quick start

The minimum wiring for a typical Laravel app.

**1. User model** — add the trait and hide the password:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use Mainul\PasswordPolicy\Traits\HasPasswordPolicy;

class User extends Authenticatable
{
    use HasPasswordPolicy;

    protected $hidden = ['password', 'remember_token'];
}
```

The trait records password history, stamps `password_changed_at`, clears or sets the forced-change flag,
ends the user's other sessions after a change and writes the audit entry. It also gives you:

```php
$user->passwordExpired();               // bool
$user->mustChangePassword();            // bool (temporary password in use)
$user->hasUsedPassword('Candidate#1');  // bool, checks the history
$user->passwordHistories;               // HasMany relation
$user->setTemporaryPassword($hash)->save(); // see "Temporary passwords"
```

> The package reads `config('password-policy.user_model')` (default `App\Models\User`). Change it if
> your model lives elsewhere.

**2. Routes** — attach the middleware (all are aliased by the package):

```php
// routes/web.php
Route::middleware(['auth', 'password.account_active', 'password.session_version',
                   'password.expiry', 'password.force_change', 'password.mfa'])
    ->group(function () {
        Route::get('/dashboard', DashboardController::class);
        // ...
    });

// Routes that must stay reachable so the user can fix the problem:
Route::middleware('auth')->group(function () {
    Route::get('/password/change', [PasswordController::class, 'edit'])->name('password.change');
    Route::put('/password', [PasswordController::class, 'update'])->name('password.update');
});

Route::middleware('password.secure')->group(function () {   // HTTPS + no secrets in the URL
    Route::post('/login', [LoginController::class, 'store']);
    Route::post('/forgot-password', ...)->middleware('password.block_self_reset');
    Route::post('/reset-password', ...);
});
```

| Alias | Put it on | What it does | Policy |
|---|---|---|---|
| `password.expiry` | authenticated routes | Redirects (or `403 password_expired` for JSON) when the password has expired | 3.5.1 |
| `password.force_change` | authenticated routes | Blocks everything until a temporary password is replaced | 3.1.5 |
| `password.account_active` | authenticated routes | Logs out disabled or overdue accounts | 3.4.2, 3.5.1, 3.8.3 |
| `password.session_version` | authenticated routes | Invalidates sessions older than the last forced termination | 3.5.2, 3.8.4 |
| `password.mfa` | authenticated routes | Requires the second factor | 3.4.3, 3.4.4, 3.9.2 |
| `password.secure` | login, password, reset routes | HTTPS only, no passwords in query strings | 3.3 |
| `password.block_self_reset` | forgot/reset-password routes | Blocks restricted roles from self-reset | 3.6.6 |

Routes named in `middleware.excluded_routes` (default `password.change`, `password.update`, `logout`) and
paths in `middleware.excluded_paths` are skipped by the expiry and forced-change checks. Make sure your
change-password routes use those names (or add yours to the config).

**3. Login action** — call the guard **before** checking credentials:

```php
use Mainul\PasswordPolicy\Exceptions\AccountLockedException;
use Mainul\PasswordPolicy\Services\LoginGuard;

public function store(Request $request)
{
    try {
        app(LoginGuard::class)->ensureCanAttempt($request->input('email'));
    } catch (AccountLockedException $e) {
        // One generic message for locked, disabled and expired accounts.
        return back()->withErrors(['email' => $e->getMessage()]);
    }

    if (! Auth::attempt($request->only('email', 'password'), $request->boolean('remember'))) {
        return back()->withErrors(['email' => 'These credentials do not match our records.']);
    }

    $request->session()->regenerate();
    return redirect()->intended('/dashboard');
}
```

Laravel's `Failed` and `Login` events feed the lockout counters and audit log automatically.

**4. Change-password form** — validate with the package rules:

```php
use Mainul\PasswordPolicy\Rules\{CurrentPasswordRule, PasswordNotReusedRule, PasswordPolicyRule};

public function update(Request $request)
{
    $user = $request->user();

    $request->validate([
        // Rule objects are skipped for missing fields, so also mark the field `required`.
        'current_password' => ['required', new CurrentPasswordRule($user)],
        'password' => ['required', 'confirmed',
            PasswordPolicyRule::for($user),       // admins get stricter rules
            new PasswordNotReusedRule($user)],
    ]);

    $user->update(['password' => Hash::make($request->password)]);
    // The trait stores history, stamps the date, audits, and ends other sessions.

    return redirect('/dashboard')->with('status', 'Password changed.');
}
```

**5. Schedule** — `password-policy:disable-expired` is scheduled daily automatically. Add the others yourself:

```php
// routes/console.php (Laravel 11+) or app/Console/Kernel.php
Schedule::command('password-policy:rotation-due --notify')->daily();
```

**6. Gates** — audit-log and API-admin access is denied to everyone until you define it:

```php
// app/Providers/AppServiceProvider.php
Gate::define('view-password-audit-logs', fn ($user) => $user->isSecurityOfficer());
```

## Feature guide

### 1. Password rules

`PasswordPolicyRule` checks a candidate password against `config('password-policy.rules')`.

| Config key | Default | Effect |
|---|---|---|
| `rules.min_length` | `11` | Minimum characters |
| `rules.require_uppercase` / `lowercase` / `numeric` / `special` | `true` | Required character classes |
| `rules.forbid_personal_info` | `true` | Rejects name parts, email local part, phone number, birthdate (needs a user) |
| `rules.banned_words` | `['password','welcome','admin','qwerty','letmein','changeme']` | Rejects passwords containing any word (case-insensitive) |
| `rules.forbid_patterns` | `true` | Rejects 4+ repeated (`aaaa`) or sequential (`1234`, `abcd`, `dcba`) characters |

**Usage in a Form Request or controller:**

```php
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;

// Without a user: global rules; the personal-info check is skipped.
$request->validate(['password' => ['required', new PasswordPolicyRule()]]);

// With a user: admin accounts get the stricter admin rules + personal-info check.
$request->validate(['password' => ['required', PasswordPolicyRule::for($request->user())]]);
```

**Registration (no user yet).** Use the string alias and (optionally) the personal-info check after creating the
record:

```php
$request->validate(['password' => ['required', 'confirmed', 'password_policy']]);
```

**Custom messages.** The failure message lists what is missing:
`The password must contain at least 11 characters, one special character.` To customise, pass your own message
for the rule in your `lang` file or build the check in a closure using `(new PasswordPolicyRule($user))->passes('password', $value)`.

**Configure the banned list** with company terms in `config/password-policy.php`:

```php
'rules' => [
    'min_length'   => 12,
    'banned_words' => ['password', 'welcome', 'acme', 'summer2024'],
],
```

The birthdate is read from `columns.birthdate` (default `date_of_birth`); name, email and phone columns come from
`columns.*`.

**Quick check from Tinker:**

```php
(new PasswordPolicyRule())->passes('password', 'Abcd1234!x');   // false, pattern "abcd"/"1234"
(new PasswordPolicyRule())->passes('password', 'Tr1cky#Horse9'); // true
```

### 2. Password history (no reuse)

Enabled by default (`history.enabled`, `history.max_reuse_count = 5`). The trait saves the **old hash** to
`password_histories` on every change; `PasswordNotReusedRule` compares a new plain password against the last N.

```php
use Mainul\PasswordPolicy\Rules\PasswordNotReusedRule;

$request->validate([
    'password' => ['required', new PasswordNotReusedRule($user)],
]);

// Programmatic check:
if ($user->hasUsedPassword($request->password)) {
    // reject
}
```

Admins can have a different count via `admin.history_count`; the stricter value applies.

### 3. Current-password confirmation

Voluntary changes must prove knowledge of the current password (3.5.4).

```php
use Mainul\PasswordPolicy\Rules\CurrentPasswordRule;

$request->validate([
    'current_password' => ['required', new CurrentPasswordRule($user)],
]);
```

The rule is **skipped** for system-forced changes: when the user has a temporary password
(`current_password.skip_when_forced`) or the password has expired (`skip_when_expired`). For an administrator
resetting someone else's password, simply do not apply the rule. In such a form, drop `required` for
`current_password` when the user is forced to change, as the API does:

```php
$rule = new CurrentPasswordRule($user);
$needsCurrent = ! $rule->passes('current_password', '');   // false when forced/expired
$request->validate(['current_password' => $needsCurrent ? ['required', $rule] : []]);
```

### 4. Password expiry

```php
// config/password-policy.php
'expiry' => [
    'enabled'      => true,
    'days'         => 30,   // maximum password age
    'grace_days'   => 1,    // disable the account this many days after expiry
    'auto_disable' => true, // schedule the daily sweep + disable on the spot in middleware
],
```

**Prompt users** — add `password.expiry` to authenticated routes. Web requests are redirected to
`middleware.password_change_route` (`password.change`) with a warning; JSON requests get
`403 {"error": "password_expired"}`.

**Disable overdue accounts** — one day after expiry (configurable). Runs daily through the scheduler, on demand
with the command, or from code:

```bash
php artisan password-policy:disable-expired --dry-run   # list what would be disabled
php artisan password-policy:disable-expired
```

```php
use Mainul\PasswordPolicy\Services\ExpiredAccountSweeper;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;

app(PasswordExpiryService::class)->isExpired($user);      // password older than allowed?
app(PasswordExpiryService::class)->isDisableDue($user);   // past expiry + grace?
app(ExpiredAccountSweeper::class)->sweep(dryRun: true);   // count of accounts affected
```

Service accounts follow a rotation schedule instead of expiry (see [13](#13-service-accounts-and-rotation)).

### 5. Temporary passwords

Used when an administrator creates an account or resets a password for someone. The password is random, never
returned, delivered only by an approved channel, and **must be changed at first login**.

```php
use Mainul\PasswordPolicy\Services\TemporaryPasswordService;
use Mainul\PasswordPolicy\Exceptions\{NoSecureChannelException, DeliveryFailedException};

try {
    $channel = app(TemporaryPasswordService::class)->issueFor($user);   // "mail" or "sms"
} catch (NoSecureChannelException $e) {
    // user has neither a company email nor a registered phone — nothing was changed
} catch (DeliveryFailedException $e) {
    // send failed — the password change was rolled back
}
```

- **Channel order**: `temporary_password.delivery_order` (`['mail', 'sms']`). Company email first; SMS only when
  there is no usable email (3.1.3). There is never an unprotected fallback.
- **Company email only**: `temporary_password.company_email_domains = ['acme.com']`.
- **Policy-compliant**: generated passwords satisfy your rules, skip look-alike characters (`0 O 1 l I`) and avoid
  anything resembling the user's personal data.
- **Forced change**: `issueFor()` sets `must_change_password`; the `password.force_change` middleware then
  blocks every route except those in `middleware.excluded_routes`.
- **SMS** needs `composer require xenon/laravelbdsms` and a `phone` column (`columns.phone`).

**Automatic on user creation** (off by default): set `temporary_password.auto_issue_on_create => true` and every
user created through a model using `HasPasswordPolicy` gets a temporary password issued and delivered right after
the insert, replacing whatever password was passed to `create()` (supply any placeholder if the column is required).
A missing channel or failed delivery never blocks the creation: the error is reported and audited, and you can
re-issue later with `issueFor()`. To skip some users (e.g. self-registration), override on the model:

```php
public function shouldIssueTemporaryPassword(): bool
{
    return ! $this->self_registered;
}
```

**Add your own channel** (e.g. WhatsApp, Slack DM):

```php
use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\PasswordDeliveryChannel;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;

class WhatsAppChannel implements PasswordDeliveryChannel
{
    public function name(): string { return 'whatsapp'; }

    public function canDeliverTo(Authenticatable $user): bool
    {
        return filled($user->whatsapp_number);
    }

    public function send(Authenticatable $user, string $temporaryPassword): void
    {
        $this->sendText($user, "Your temporary password: {$temporaryPassword}", 'Temporary password');
    }

    public function sendText(Authenticatable $user, string $text, ?string $subject = null): void
    {
        // call your gateway; throw DeliveryFailedException on failure; NEVER log $text
    }
}

// config/password-policy.php
'temporary_password' => [
    'delivery_order' => ['mail', 'whatsapp', 'sms'],
    'channels' => [
        'mail'     => \Mainul\PasswordPolicy\Delivery\MailChannel::class,
        'sms'      => \Mainul\PasswordPolicy\Delivery\SmsChannel::class,
        'whatsapp' => \App\Security\WhatsAppChannel::class,
    ],
],
```

**Generate only** (no delivery), e.g. for tests or seeding:

```php
$plain = app(TemporaryPasswordService::class)->generate(length: 16, forUser: $user);
$user->setTemporaryPassword(Hash::make($plain))->save();
```

### 6. Account lockout

Tiered lockout after repeated failures (3.4.1, 3.4.2):

```php
'lockout' => [
    'enabled'           => true,
    'max_attempts'      => 5,          // consecutive failures per cycle
    'durations'         => [5, 10, 30],// minutes for the 1st, 2nd, 3rd lock
    'extended_minutes'  => 120,        // every later lock — also needs identity verification to unlock
    'reset_after_hours' => 24,
    'ip_burst'          => ['enabled' => true, 'attempts' => 5, 'window_seconds' => 60],
],
```

An IP burst (5 failures from one IP against one account in 60 s) locks the account **permanently** until an
administrator unlocks it.

**Block sign-ins** with `LoginGuard` (see [Quick start](#quick-start)). It also disables accounts that are past
expiry. The exception exposes details for your UI:

```php
catch (AccountLockedException $e) {
    $e->retryAfterSeconds; // ?int — null for permanent/verification locks
    $e->reason;            // 'disabled' | 'temporary' | 'permanent' | 'verification'
                           // (show users the generic message; keep the reason for your own logs)
}
```

**Manage locks from code** (administrator actions are audited):

```php
use Mainul\PasswordPolicy\Services\LockoutService;

$lockout = app(LockoutService::class);

$lockout->lockState($user);                 // ['type' => 'temporary|verification|permanent', 'until' => Carbon|null] or null
$lockout->isLocked($user);                  // bool
$lockout->lock($user, $admin, 'Suspicious activity');       // permanent administrator lock
$lockout->unlock($user, verifiedBy: $admin);                // $verifiedBy is required for permanent/verification locks
```

From the CLI there is no unlock command; use the API (`POST admin/users/{id}/unlock`) or the service above.

Listen for `AccountLocked` to notify the user or SOC (see [Events](#events)).

### 7. Disable, enable and compromise accounts

```php
use Mainul\PasswordPolicy\Services\AccountService;

$accounts = app(AccountService::class);

$accounts->disable($user, 'Left the company', actor: $admin);   // blocks sign-in, ends sessions
$accounts->enable($user, actor: $admin);                        // re-enables and forces a password change
$accounts->markCompromised($user, actor: $admin);               // 3.7.5: password made unusable,
                                                                // every session/token ended, change forced
$accounts->isDisabled($user);
```

`markCompromised()` dispatches the `PasswordCompromised` event. Follow it with
`TemporaryPasswordService::issueFor($user)` once identity is verified.

### 8. Session termination

On a password change the trait ends the user's **other** sessions and API tokens, so the old password stops
working everywhere (3.5.2). The session/token that made the change stays signed in. Disable with
`sessions.terminate_on_password_change = false`.

```php
use Mainul\PasswordPolicy\Services\SessionTerminator;

app(SessionTerminator::class)->terminate($user);                                    // everything
app(SessionTerminator::class)->terminate($user, keepCurrent: true, reason: 'manual'); // keep this session
```

It bumps the user's `session_version` (enforced by `password.session_version`), clears database sessions and
deletes Sanctum/Passport tokens.

### 9. Password reset protection

**Restrict roles that may not self-reset (3.6.6).**

```php
'reset' => [
    'restricted_roles' => ['BA', 'SO'],      // must contact an administrator
    'role_attribute'   => 'role',            // string or array attribute on the user
    'role_resolver'    => \App\Security\RoleResolver::class, // optional, wins over role_attribute
],
```

```php
// App\Security\RoleResolver — invokable, returns a role name or list of roles
class RoleResolver
{
    public function __invoke($user): array { return $user->roles()->pluck('name')->all(); }
}
```

```php
// Forgot-password route:
Route::post('/forgot-password', [...])->middleware('password.block_self_reset');

// or as a validation rule:
$request->validate(['email' => ['required', 'email', new \Mainul\PasswordPolicy\Rules\CanSelfResetPassword()]]);
```

**Independent identity check (3.6.2).** Send and verify a one-time code before accepting the new password —
especially useful for phone-only users:

```php
use Mainul\PasswordPolicy\Contracts\ResetIdentityVerifier;

$verifier = app(ResetIdentityVerifier::class);

// Step 1: user asks for a reset
$channel = $verifier->issue($user);                  // code goes to company email, else phone

// Step 2: user submits the code with the new password
if (! $verifier->verify($user, $request->code)) {    // single use, 10 min, locks after 5 wrong tries
    abort(422, 'Invalid or expired code.');
}
$user->update(['password' => Hash::make($request->password)]);
event(new \Illuminate\Auth\Events\PasswordReset($user));   // audit + "your password was reset" notice
```

Tune with `reset.code_length` (6), `reset.code_ttl_minutes` (10), `reset.code_max_attempts` (5). Replace the verifier by
setting `reset.verifier` to your class implementing `ResetIdentityVerifier`.

**Reset notice (3.6.5).** When `reset.notify` is true, Laravel's `PasswordReset` event sends the user a notice
(never containing a password). **Link expiry** — `password-policy:check` fails if a broker's `expire` exceeds
`reset.max_expire_minutes` (60).

### 10. Authenticator-app MFA (TOTP)

Optional second step: the user types the 6-digit code from Google/Microsoft Authenticator, Authy or similar.
**Off by default.** Once enabled, it is required, and users without an app are sent to a set-up page.

```bash
php artisan migrate
php artisan password-policy:totp --enable --scope=all --grace-days=7
php artisan password-policy:totp --status
```

**Option A — bundled pages.** In the config set `totp.routes => true` (adds `mfa/enroll`, `mfa/challenge`,
`mfa/recovery-codes`; route names `mfa.enroll`, `mfa.enroll.confirm`, `mfa.challenge`, `mfa.verify`,
`mfa.recovery`). Then add the middleware:

```php
Route::middleware(['auth', 'password.mfa'])->group(function () { /* protected routes */ });
```

After a password login `password.mfa` redirects to the set-up page (no app yet) or the code page (app set up,
code not yet entered). Restyle with `vendor:publish --tag=password-policy-views`.

**Option B — build your own UI** on `TotpEnrollmentService`:

```php
use Mainul\PasswordPolicy\Services\{TotpEnrollmentService, MfaService};

$totp = app(TotpEnrollmentService::class);

// Enrolment
$data = $totp->begin($user);                 // ['secret' => 'JBSWY3DP...', 'uri' => 'otpauth://totp/...']
// render $data['uri'] as a QR code (or show $data['secret'])
$recovery = $totp->confirm($user, $request->code);   // array of recovery codes (shown ONCE) or null if the code is wrong

// Sign-in challenge
$mfa = app(MfaService::class);
if ($mfa->isRequired($user, $request) && ! $mfa->isVerified($user, $request)) {
    if ($mfa->verify($user, $request->code, $request)) {   // accepts a TOTP code or a recovery code
        return redirect()->intended();
    }
    // wrong code — counts toward the account lockout
}

// Management
$totp->recoveryCodesRemaining($user);
$totp->regenerateRecoveryCodes($user);
$totp->reset($user, actor: $admin);          // lost phone: user re-enrols at next login
```

**Config or database?** `totp.*` in `config/password-policy.php` are defaults. The `password_policy_settings` table
overrides `totp.enabled`, `totp.scope`, `totp.grace_days` and `totp.issuer` (the database wins) — change them with
`password-policy:totp` or `PUT admin/settings` so the change is audited. To pin the policy in code set
`totp.enabled = true` **and** `totp.lock_to_config = true`.

```php
use Mainul\PasswordPolicy\Services\SettingsRepository;

$settings = app(SettingsRepository::class);
$settings->get('totp.scope');                 // effective value (db wins over config)
$settings->set('totp.scope', 'admins', $admin);
$settings->forget('totp.scope', $admin);      // back to the config default
```

| Option | Meaning |
|---|---|
| `totp.scope` | `all`, `admins`, or `remote` (outside `mfa.internal_networks`). Admins always need MFA. |
| `totp.grace_days` | Days after `--enable` that unenrolled users can still sign in. Enrolled users are always challenged. Enabling through config alone gives no grace period. |
| `totp.issuer` | Name shown in the app (defaults to app name). |
| `totp.window` | Clock drift accepted either side (1 = ±30 s). |
| `totp.recovery_codes` | How many backup codes (default 8). |
| `mfa.internal_networks` | CIDR list of trusted networks, e.g. `['10.0.0.0/8', '192.168.1.0/24']`. |
| `mfa.require_all` | Require MFA for every user. |

**Security notes.** The secret is stored **encrypted** with `APP_KEY` (changing the key makes secrets unreadable,
so users would need a reset). Recovery codes are keyed hashes shown once. A code can be used once (replay
blocked), wrong codes count toward lockout, the session id is renewed on success, and an enrolled app can not be
replaced from a password-only session. If the settings table is unreachable, config defaults are used.

### 11. Custom MFA driver

Prefer SMS, e-mail OTP or push? Implement `MfaDriver` and point `mfa.driver` at it. A driver you configure takes
priority over the built-in one.

```php
use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\MfaDriver;

class SmsCodeDriver implements MfaDriver
{
    public function isEnrolled(Authenticatable $user): bool
    {
        return filled($user->phone);
    }

    public function challenge(Authenticatable $user): void     // send the code
    {
        $code = random_int(100000, 999999);
        Cache::put("sms-mfa:{$user->id}", Hash::make((string) $code), now()->addMinutes(5));
        Sms::to($user->phone)->send("Your login code: {$code}");
    }

    public function verify(Authenticatable $user, string $code): bool
    {
        $hash = Cache::pull("sms-mfa:{$user->id}");          // pull = single use
        return $hash && Hash::check($code, $hash);
    }
}

// config/password-policy.php
'mfa' => [
    'driver'            => \App\Security\SmsCodeDriver::class,
    'require_remote'    => true,
    'internal_networks' => ['10.0.0.0/8'],
    'require_all'       => false,
    'token_ttl_minutes' => 720,   // API tokens: how long a passed MFA stays valid
],
```

Who needs MFA: **admins always**; plus remote users (`require_remote` with a non-empty `internal_networks`) and
everyone if `require_all` is true. With no factor available, users who need MFA are **blocked** (fail closed).
Enrolment endpoints answer `404 mfa_external_driver` with a host driver because set-up is your driver's job.

### 12. Admin accounts

Admins (a role in `admin.roles` or a truthy `admin.flag_attribute`) get stricter rules; the stricter of the global
and admin value applies.

```php
'admin' => [
    'roles'               => ['ADMIN', 'SUPER_ADMIN', 'SUPERADMIN'],
    'flag_attribute'      => 'is_admin',
    'rules'               => ['min_length' => 14],  // any key from `rules` can be overridden
    'expiry_days'         => 60,
    'history_count'       => 5,
    'daily_email_domains' => ['gmail.com', 'acme.com'], // admins logging in with these are flagged
],
```

```php
PasswordPolicyRule::for($admin);   // 14+ characters
app(\Mainul\PasswordPolicy\Services\AccountClassifier::class)->isAdmin($user);
app(\Mainul\PasswordPolicy\Services\PolicyProfile::class)->expiryDays($user);
```

`password-policy:check` flags admins whose login email is on a daily-use domain (3.9.1).

### 13. Service accounts and rotation

Service accounts (bots, integrations) need a named owner and purpose, rotate on a schedule instead of expiring,
and never sign in interactively.

```php
use Mainul\PasswordPolicy\Services\ServiceAccountService;

$svc = app(ServiceAccountService::class);

$svc->register($botUser, owner: 'Jane Doe', purpose: 'Nightly ETL', rotationDays: 90, knownBy: [12, 15]);
$svc->update($botUser, ['owner' => 'John Roe', 'rotation_days' => 60]);
$svc->due();                    // Collection of accounts whose rotation is overdue
$svc->notifyDue();              // emails owners + service_accounts.notify_recipients; returns count
$svc->rotate($botUser);         // new random secret -> vault; rolled back if the vault fails
$svc->remove($botUser);         // stop treating the user as a service account
```

`knownBy` lists the ids of people who know the password; offboarding one of them marks the account due.

**Vault callback.** The package never keeps or returns the secret; rotation is refused without a vault.

```php
// config/password-policy.php
'service_accounts' => [
    'default_rotation_days' => 90,
    'password_length'       => 32,
    'vault'                 => \App\Security\VaultWriter::class,
    'notify_recipients'     => ['security@acme.com'],
],

// App\Security\VaultWriter — invokable
class VaultWriter
{
    public function __invoke(Authenticatable $user, string $secret): void
    {
        Vault::put("service-accounts/{$user->id}", ['password' => $secret]);   // throw to abort + roll back
    }
}
```

```bash
php artisan password-policy:rotation-due              # list overdue
php artisan password-policy:rotation-due --notify     # email owners
php artisan password-policy:rotation-due --rotate     # rotate through the vault
```

### 14. Offboarding leavers

Disables the account the same day, ends every session/token and flags service-account passwords the person knew:

```bash
php artisan password-policy:offboard jane@acme.com --actor=admin@acme.com
```

```php
use Mainul\PasswordPolicy\Services\OffboardingService;

$mustRotate = app(OffboardingService::class)->offboard($user, actor: $admin);
// Collection<ServiceAccount> — their next_rotation_at is now, so `rotation-due` picks them up
foreach ($mustRotate as $account) {
    app(ServiceAccountService::class)->rotate($account->user);
}
```

### 15. Audit log

Logins, failures, lockouts, password changes, resets, MFA, admin actions, etc. are written to
`password_audit_logs` **without secrets** (keys in `audit.redact_keys` are redacted, e.g. `password`, `token`,
`code`, `otp`).

```php
// Reading is denied until YOU define the ability (3.7.3):
Gate::define('view-password-audit-logs', fn ($user) => in_array($user->role, ['SECURITY', 'AUDITOR']));

// Query it
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
PasswordAuditLog::where('user_id', $id)->where('outcome', 'failure')->latest()->take(50)->get();

// Write your own entry
use Mainul\PasswordPolicy\Services\AuditLogger;
app(AuditLogger::class)->log('report_exported', AuditLogger::OUTCOME_SUCCESS, $user, null, ['rows' => 120]);
// outcomes: success | failure | blocked | alert
```

```bash
php artisan password-policy:audit --user=jane@acme.com --event=login --outcome=failure --limit=50
```

**Keep secrets out of application logs (3.7.2)** — add the tap to a channel in `config/logging.php`:

```php
'single' => [
    'driver' => 'single',
    'path'   => storage_path('logs/laravel.log'),
    'tap'    => [\Mainul\PasswordPolicy\Logging\RedactSensitiveData::class],
],
```

Also available: `Mainul\PasswordPolicy\Support\Redactor::redact($array)`.

### 16. Unusual-login detection

Alerts when an account collects `anomaly.failure_threshold` failures within `anomaly.window_minutes`, or when a
successful login comes from a **new network** (IPv4 /24, IPv6 /48 by default) or, with a resolver, a **new
country**. The first login only sets the baseline. Each alert is audited, emailed to `anomaly.alert_recipients`
and dispatched as `UnusualLoginDetected`.

```php
// Optional country check — implement the contract with any GeoIP library
use Mainul\PasswordPolicy\Contracts\GeoResolver;

class MaxMindGeo implements GeoResolver
{
    public function country(string $ip): ?string
    {
        return GeoIP::getLocation($ip)->iso_code ?? null;   // two-letter code or null
    }
}

// config
'anomaly' => [
    'enabled'           => true,
    'failure_threshold' => 3,
    'window_minutes'    => 10,
    'geo_resolver'      => \App\Security\MaxMindGeo::class,
    'alert_recipients'  => ['soc@acme.com'],
],
```

No external geo service is bundled.

### 17. Secure transport (HTTPS)

`password.secure` rejects non-HTTPS requests (3.3.1) and requests carrying secrets in the query string (3.3.2).
It is active only when `APP_ENV=production` unless forced:

```php
'tls' => [
    'enforce'              => null,   // null = production only, true = always, false = never
    'forbidden_query_keys' => ['password', 'current_password', 'pwd', /* ... */],
],
```

```php
Route::post('/login', ...)->middleware('password.secure');
```

Behind a proxy/load balancer, configure Laravel's trusted proxies so `$request->secure()` is correct.

### 18. Default-password scan

Before go-live, find accounts still using a known default password (3.9.5). Add your vendor defaults to
`defaults.passwords`.

```bash
php artisan password-policy:check-defaults              # report
php artisan password-policy:check-defaults --flag       # also force those users to change
php artisan password-policy:check-defaults --user=42    # one user
```

```php
$result = app(\Mainul\PasswordPolicy\Services\DefaultPasswordScanner::class)->scan(flag: true);
```

It hashes each candidate per user, so it is slow on large tables: run it off-peak.

## JSON API

Everything above is also available over HTTP, for mobile apps, SPAs and other services. It is **off by default**:
the routes exist but answer `404` until enabled, either in the config or at runtime without a deploy:

```php
// config/password-policy.php
'api' => ['enabled' => true],

// or at runtime
app(\Mainul\PasswordPolicy\Services\SettingsRepository::class)->set('api.enabled', true);
```

**Authentication.** The guard is `sanctum` by default (`composer require laravel/sanctum`). For Passport, set
`api.guard` to the guard whose driver is `passport` (usually `api`); a list such as `['sanctum', 'api']` tries each
in turn. It can be set in the config or in the database (`api.guard`); the database wins and is read on every request.

**Authorization.** `/admin` endpoints are checked against Gate abilities that **deny everyone until you define
them**:

```php
Gate::define('password-policy.manage-users',            fn ($user) => $user->isSecurityOfficer());
Gate::define('password-policy.manage-service-accounts', fn ($user) => $user->isSecurityOfficer());
Gate::define('password-policy.manage-settings',         fn ($user) => $user->isSecurityOfficer());
Gate::define('password-policy.view-compliance',         fn ($user) => $user->isSecurityOfficer());
Gate::define('view-password-audit-logs',                fn ($user) => $user->isSecurityOfficer());
```

By default `/admin` also sits behind `password.expiry`, `password.force_change` and `password.mfa`
(`api.admin_requires_mfa`, read when routes load), so admins need an enrolled authenticator first.

Paths are relative to `api.prefix` (default `/api/password-policy`). Errors are JSON:
`{"message": "...", "error": "code"}`, or Laravel's `{"errors": {...}}` for validation. Throttling:
`api.throttle.public` (`6,1`) for anonymous endpoints, `api.throttle.sensitive` (`10,1`) for secret-checking ones.

### Endpoints

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
| `POST mfa/enroll/confirm` | signed in | `code` from the app. Returns recovery codes once. |
| `POST mfa/challenge` | signed in | Start a challenge for drivers that need one (send an SMS code). |
| `POST mfa/verify` | signed in | `code` (or a recovery code). Marks **this token** as MFA-verified. |
| `POST mfa/recovery-codes` | signed in | `password`. New recovery codes; needs a verified token. Built-in app only. |
| `GET admin/users/{id}` | users | Security state of an account. |
| `GET admin/users/{id}/known-logins` | users | Networks/countries the user signed in from. |
| `POST admin/users/{id}/lock` | users | `reason` optional. Permanent lock. |
| `POST admin/users/{id}/unlock` | users | `verified_by` required for permanent and identity-verification locks. |
| `POST admin/users/{id}/disable`, `.../enable` | users | `reason` optional. Enabling forces a password change. |
| `POST admin/users/{id}/compromise` | users | Make the password unusable and end every session (3.7.5). |
| `POST admin/users/{id}/temporary-password` | users | Send a new temporary password to the approved channel (never returned). |
| `POST admin/users/{id}/terminate-sessions` | users | End all sessions and API tokens. |
| `POST admin/users/{id}/offboard` | users | Disable a leaver and list the shared passwords to rotate. |
| `DELETE admin/users/{id}/mfa` | users | Wipe a user's authenticator app (lost device). |
| `POST admin/accounts/disable-expired` | users | `dry_run` optional. Disable accounts past expiry plus grace. |
| `GET admin/service-accounts[?due=1]` | service accounts | List. |
| `POST admin/service-accounts` | service accounts | `user_id`, `owner`, `purpose`, `rotation_days`, `known_by[]`. |
| `PUT`, `DELETE admin/service-accounts/{id}` | service accounts | Update, or stop treating the user as a service account. |
| `POST admin/service-accounts/{id}/rotate`, `.../rotate-due` | service accounts | Rotate through your vault. |
| `POST admin/service-accounts/notify-due` | service accounts | Email owners about overdue rotations. |
| `GET`, `PUT admin/settings`, `DELETE admin/settings/{key}` | settings | Database overrides: `totp.*`, `api.enabled`, `api.guard`. |
| `GET admin/audit` | audit gate | Filters: `user_id`, `event`, `outcome`, `from`, `to`, `per_page`. |
| `GET admin/compliance` | compliance | The `password-policy:check` self-test. |
| `POST admin/compliance/default-passwords`, `GET .../{scan_id}` | users | Default-password scan (queued unless `user_id` is given). |

### Examples

**Mobile login flow** (your login endpoint issues the Sanctum token):

```bash
# 1. May this account try a password?
curl -X POST https://app.test/api/password-policy/login/check \
  -H 'Accept: application/json' -d 'email=jane@acme.com'
# 200 {"allowed": true}
# 423 {"message": "This account is currently unavailable...", "error": "account_unavailable", "retry_after": 300}

# 2. After your own login returns a token, check the password state
curl https://app.test/api/password-policy/password/status \
  -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"
# {"data": {"expired": false, "days_remaining": 12, "must_change_password": false,
#           "mfa": {"required": true, "enrolled": true, "verified": false}}}
```

**Change password:**

```bash
curl -X PUT https://app.test/api/password-policy/password \
  -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN" \
  -d 'current_password=Old#Passw0rd1' -d 'password=N3w#Secret-Pass' -d 'password_confirmation=N3w#Secret-Pass'
# 200 {"message": "Password changed."}
# 422 {"errors": {"password": ["The password must contain ..."]}}
```

`current_password` may be omitted when the password is temporary or expired.

**Pre-validate while the user types** (changes nothing):

```bash
curl -X POST .../password/validate -H "Authorization: Bearer $TOKEN" -d 'password=abc'
# {"valid": false, "errors": ["The password must contain at least 11 characters, ..."]}
```

**Forgotten password (not signed in):**

```bash
curl -X POST .../reset/code     -d 'email=jane@acme.com'            # always 202
curl -X POST .../reset/password -d 'email=jane@acme.com' -d 'code=482913' \
     -d 'password=N3w#Secret-Pass' -d 'password_confirmation=N3w#Secret-Pass'
```

**Authenticator app from a mobile client:**

```bash
curl -X POST .../mfa/enroll -H "Authorization: Bearer $TOKEN"
# {"data": {"secret": "JBSW...", "uri": "otpauth://totp/...", "qr_svg": "<svg ...>"}}
curl -X POST .../mfa/enroll/confirm -H "Authorization: Bearer $TOKEN" -d 'code=123456'
# {"data": {"recovery_codes": ["ABCD-EFGH", ...]}}     <- shown once
curl -X POST .../mfa/verify -H "Authorization: Bearer $TOKEN" -d 'code=654321'
```

**Admin: unlock an account, switch the API guard:**

```bash
curl -X POST .../admin/users/42/unlock -H "Authorization: Bearer $ADMIN_TOKEN" -d 'verified_by=helpdesk-17'

curl -X PUT .../admin/settings -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H 'Content-Type: application/json' -d '{"settings": {"api.guard": "api", "totp.scope": "admins"}}'
```

**Notes**

- **MFA for tokens.** There is no session, so a passed code is remembered per bearer token in the cache for
  `mfa.token_ttl_minutes` (12 h). Use a shared cache store on more than one server. Cookie-based SPA requests use the session.
- **Reset codes.** `reset/password` spends the code before the checks that need the user (reuse, personal info),
  so they cannot be used to probe accounts. If one fails, request a new code.
- **Not part of the API**: the login action itself (use `login/check` before yours) and the Laravel reset-*link*
  flow (the API's own reset applies the same restricted-role rule).

## Commands

| Command | Purpose |
|---|---|
| `password-policy:check` | Self-test: hashing driver, hidden password, HTTPS in production, reset link expiry, MFA driver, admin separation, SMS dependency, TOTP enrolment count. Exits non-zero on failure. Run it in CI/deploy. |
| `password-policy:check-defaults [--flag] [--user=]` | Find accounts using a known default password (3.9.5). |
| `password-policy:disable-expired [--dry-run]` | Disable accounts unchanged past expiry plus grace. |
| `password-policy:rotation-due [--notify] [--rotate]` | List, notify about, or rotate overdue service accounts. |
| `password-policy:offboard {user} [--actor=]` | Disable a leaver and flag the shared passwords they knew. |
| `password-policy:totp [--enable] [--disable] [--status] [--scope=] [--grace-days=] [--reset=] [--actor=]` | Control the authenticator-app login or wipe a user's app. |
| `password-policy:audit [--user= --event= --outcome= --limit=]` | Show recent audit entries (server access only). |

## Events

| Event | When | Properties |
|---|---|---|
| `Events\AccountLocked` | An account is locked | `user`, `reason`, `level`, `minutes` |
| `Events\PasswordCompromised` | `markCompromised()` ran | `user`, `reportedBy` |
| `Events\UnusualLoginDetected` | Repeated failures / new network / new country | `user`, `identifier`, `reasons[]`, `ip` |

```php
// app/Providers/EventServiceProvider.php or AppServiceProvider::boot()
Event::listen(AccountLocked::class, function (AccountLocked $e) {
    Slack::to('#security')->send("Account {$e->user->email} locked ({$e->reason}, level {$e->level}).");
});

Event::listen(UnusualLoginDetected::class, fn ($e) => Log::warning('Unusual login', [
    'user' => $e->user?->getAuthIdentifier(), 'reasons' => $e->reasons, 'ip' => $e->ip,
]));
```

The package also listens to Laravel's `Login`, `Failed`, `Lockout` and `PasswordReset` events.

## Configuration

Everything lives in `config/password-policy.php` and is documented inline. Groups:

| Group | Purpose |
|---|---|
| `rules` | Complexity, personal info, banned words, patterns |
| `expiry` | Max age, grace period, auto-disable |
| `history` | Reuse prevention |
| `lockout` | Attempts, durations, IP burst |
| `temporary_password` | Length, delivery order/channels, company domains |
| `reset` | Restricted roles, role resolver, one-time codes, notice |
| `anomaly` | Unusual-login thresholds, geo resolver, alert recipients |
| `tls` | HTTPS enforcement, forbidden query keys |
| `audit` | Enable, gate ability, redaction keys |
| `mfa`, `totp` | MFA scope, driver, authenticator-app options |
| `api` | Enable, guard, prefix, throttle, abilities |
| `admin` | Admin identification and stricter values |
| `service_accounts` | Rotation, vault, recipients |
| `defaults` | Known default passwords |
| `sessions` | Terminate on password change |
| `columns` | User column names (`email`, `phone`, `name`, `birthdate`) |
| `current_password` | When the current-password rule is skipped |
| `middleware` | Excluded routes/paths and the change-password route |
| `user_model` | Your User class |

**Common recipes**

```php
// Relaxed, e.g. an internal tool: 12 chars, 90-day expiry, no personal-info check
'rules'  => ['min_length' => 12, 'forbid_personal_info' => false],
'expiry' => ['days' => 90],

// Different column names
'columns' => ['email' => 'work_email', 'phone' => 'mobile', 'name' => 'full_name', 'birthdate' => 'dob'],

// Admin flag stored in a role column
'admin' => ['roles' => ['ADMIN'], 'flag_attribute' => null],

// Turn a feature off
'lockout' => ['enabled' => false],
'history' => ['enabled' => false],
'audit'   => ['enabled' => false],
'sessions' => ['terminate_on_password_change' => false],
```

HTTPS enforcement (`tls.enforce = null`) is active only when `APP_ENV=production`; set `true`/`false` to force it.

## Things to know before relying on it

- **Shared cache**: the IP-burst counter, repeated-failure counter and API MFA state use the cache. On more
  than one server use a shared store (Redis or database), not `array` or `file`.
- **Lockout wording**: policy clause 3.4.2 does not define "second occurrence" or "extended temporary lockout".
  The defaults are an interpretation and are configurable. With the default IP burst (5 in 60 s) a person who
  mistypes 5 times in a minute is locked until an administrator unlocks them. Raise `lockout.ip_burst.attempts` if
  that is too strict.
- **MFA factor**: until you enable the built-in app (`totp.enabled`) or provide an `MfaDriver`, users who need
  MFA are blocked.
- **Self-reset block**: the response for a restricted role (BA, SO) reveals that the account exists and has that
  role. Unknown emails get the normal answer.
- **Delivery is synchronous**: temporary passwords, reset notices and alerts are sent inline, not queued.
- **Admin defaults are an assumption**: minimum length 14, expiry 60 days, history 5.
- **Not enforceable in code**: sharing or writing down passwords, reusing a password across systems, browser
  "Remember Password", keeping an admin password different from the same person's user-account password.
- **`APP_KEY`**: TOTP secrets are encrypted with it. Do not rotate it casually.

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
| 3.4.3 | MFA enforced for admin, remote, external | 🔌 | `password.mfa` + authenticator app or your `MfaDriver` |
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

The suite uses Orchestra Testbench. In your own tests you can fake delivery and MFA by binding your own classes
(see `tests/Support/FakeSmsChannel.php`, `FakeMfaDriver.php`, `FakeGeoResolver.php` for ready-made examples).

## Upgrading

- Run `php artisan migrate` after every update.
- Re-publish or merge the config to see new options: `php artisan vendor:publish --tag=password-policy-config --force`
  (this overwrites your edits, so diff first). Defaults apply without it.
- Stricter defaults (11 characters, 30-day expiry, 5-password history, personal-info/banned-word/pattern checks)
  apply at the next password change. Set the old values in your published config to keep them.
- See [CHANGELOG.md](CHANGELOG.md).

## License

MIT

---

<a id="বাংলা-ডকুমেন্টেশন"></a>

## বাংলা ডকুমেন্টেশন

`mainul/password-policy` হলো Laravel-এর জন্য একটি প্যাকেজ, যা পাসওয়ার্ড ও অ্যাকাউন্ট নিরাপত্তার বিভিন্ন নিয়ন্ত্রণ বাস্তবায়ন করে: ভ্যালিডেশন রুল, মেয়াদ, ইতিহাস, লকআউট, অস্থায়ী পাসওয়ার্ড, MFA, অডিট লগ, সার্ভিস অ্যাকাউন্ট এবং JSON API।

এর জন্য **PHP 8.2+** এবং **Laravel 10 থেকে 13** প্রয়োজন।

> প্যাকেজটি প্রয়োজনীয় নিয়ন্ত্রণ সরবরাহ করে। তবে কিছু নিয়ন্ত্রণ কার্যকর করতে আপনার অ্যাপ্লিকেশনে middleware, login action এবং Gate যুক্ত করতে হবে। নিচের প্রতিটি অংশে তা ব্যাখ্যা করা হয়েছে। একই ফাইল অপ্রয়োজনীয়ভাবে বড় ও দুই ভাষার code block অসামঞ্জস্যপূর্ণ হয়ে যাওয়া এড়াতে executable code, command, route, configuration key এবং API payload উপরের English অংশে একবারই রাখা হয়েছে। প্রতিটি বাংলা অংশের নম্বর সংশ্লিষ্ট English অংশের সঙ্গে সরাসরি মিলে যায়।

### সূচিপত্র

1. [বৈশিষ্ট্য](#বৈশিষ্ট্য)
2. [ইনস্টলেশন](#ইনস্টলেশন)
3. [দ্রুত শুরু](#দ্রুত-শুরু)
4. [বৈশিষ্ট্য নির্দেশিকা](#বৈশিষ্ট্য-নির্দেশিকা)
5. [JSON API](#json-api-1)
6. [Artisan command](#artisan-command)
7. [Event](#event)
8. [কনফিগারেশন](#কনফিগারেশন)
9. [ব্যবহারের আগে গুরুত্বপূর্ণ বিষয়](#ব্যবহারের-আগে-গুরুত্বপূর্ণ-বিষয়)
10. [নীতি-সম্মতি](#নীতি-সম্মতি)
11. [পরীক্ষা, আপগ্রেড ও লাইসেন্স](#পরীক্ষা-আপগ্রেড-ও-লাইসেন্স)

### বৈশিষ্ট্য

- **Password rules:** দৈর্ঘ্য, বড়/ছোট অক্ষর, সংখ্যা, বিশেষ চিহ্ন, ব্যক্তিগত তথ্য, নিষিদ্ধ শব্দ এবং সহজ pattern পরীক্ষা করে। Admin-এর জন্য আরও কঠোর rule প্রযোজ্য।
- **Password history:** সাম্প্রতিক পাসওয়ার্ড পুনরায় ব্যবহার বন্ধ করে।
- **Temporary password:** নিরাপদ random password তৈরি করে অনুমোদিত email/SMS channel-এ পাঠায় এবং প্রথম login-এ পরিবর্তন বাধ্যতামূলক করে।
- **Account lockout:** ধাপভিত্তিক lock period, administrator unlock এবং দ্রুত IP-based failure শনাক্ত করে।
- **Password expiry:** ব্যবহারকারীকে পরিবর্তনের বার্তা দেয় এবং অতিরিক্ত মেয়াদোত্তীর্ণ account স্বয়ংক্রিয়ভাবে disable করে।
- **Session termination:** password change, compromise বা offboarding-এর পরে web session ও API token শেষ করে।
- **Audit ও monitoring:** security event record করে, secret মুছে রাখে এবং unusual login শনাক্ত করে।
- **MFA:** built-in authenticator app (TOTP) অথবা custom driver সমর্থন করে।
- **Reset protection:** one-time identity code এবং role-based reset restriction দেয়।
- **Service account:** owner, purpose এবং vault-এর মাধ্যমে scheduled rotation পরিচালনা করে।
- **Offboarding ও command:** চলে যাওয়া কর্মীর account disable, shared credential flag এবং diagnostic চালায়।
- **JSON API:** mobile app ও SPA-এর জন্য HTTP interface দেয়; default Sanctum, Passport-ও সমর্থিত।

### ইনস্টলেশন

উপরের [Installation](#installation) অংশের command চালান। Service provider auto-discover হবে। ঐচ্ছিক package-গুলোর কাজ:

| Package | ব্যবহার |
|---|---|
| `bacon/bacon-qr-code` | authenticator setup page-এ QR code দেখায়; না থাকলে key দেখায় |
| `xenon/laravelbdsms` | company email না থাকলে SMS-এ temporary password/reset code পাঠায় |
| `laravel/sanctum` | JSON API-এর default guard |
| `laravel/passport` | বিকল্প API guard |

Publish tag দিয়ে config, migration এবং MFA view প্রকাশ করা যায়। Migration `users` table-এ password state, lockout ও session-version column যোগ করে এবং history, audit, known login, reset code, service account, MFA credential ও runtime setting-এর table তৈরি করে। `users` table-এর নাম নির্দিষ্ট। পুরোনো user যেন সঙ্গে সঙ্গে expired না হয়, তাই migration-এর সময় তাদের `password_changed_at` বসানো হয়।

### দ্রুত শুরু

সাধারণ Laravel app-এ ন্যূনতম ছয়টি integration দরকার:

1. **User model:** `HasPasswordPolicy` trait ব্যবহার করুন এবং `password`, `remember_token` hidden রাখুন। Trait history সংরক্ষণ, change time লেখা, forced-change flag, অন্য session বন্ধ এবং audit entry তৈরি করে। Model অন্য namespace-এ থাকলে `password-policy.user_model` বদলান।
2. **Route:** authenticated route-এ `password.account_active`, `password.session_version`, `password.expiry`, `password.force_change` ও `password.mfa` middleware দিন। Password change ও logout route-কে excluded route হিসেবে reachable রাখুন। Login/reset route-এ `password.secure`; restricted self-reset route-এ `password.block_self_reset` দিন।
3. **Login action:** credential পরীক্ষা করার **আগে** `LoginGuard::ensureCanAttempt()` চালান। Locked, disabled ও expired account-এর জন্য user-কে একই generic message দেখান। Laravel-এর `Failed` ও `Login` event counter ও audit স্বয়ংক্রিয়ভাবে চালায়।
4. **Password change form:** `CurrentPasswordRule`, `PasswordPolicyRule::for($user)` এবং `PasswordNotReusedRule` ব্যবহার করুন। Field-এর সঙ্গে `required`-ও দিন। Trait update-এর পর বাকি security কাজ করে।
5. **Schedule:** `password-policy:disable-expired` দৈনিক স্বয়ংক্রিয়ভাবে schedule হয়। Service-account notification/rotation command নিজে schedule করুন।
6. **Gate:** audit log এবং API admin access default-এ সবার জন্য denied। উপরের English example অনুযায়ী Gate define করুন।

Middleware alias-গুলোর উদ্দেশ্য:

| Alias | কাজ |
|---|---|
| `password.expiry` | expired password হলে redirect অথবা JSON `403` |
| `password.force_change` | temporary password বদলানো পর্যন্ত অন্য কাজ block |
| `password.account_active` | disabled/overdue account logout |
| `password.session_version` | পুরোনো session invalid |
| `password.mfa` | দ্বিতীয় factor বাধ্যতামূলক |
| `password.secure` | HTTPS নিশ্চিত এবং URL query-তে secret বন্ধ |
| `password.block_self_reset` | restricted role-এর self-reset বন্ধ |

### বৈশিষ্ট্য নির্দেশিকা

#### ১. Password rule

`PasswordPolicyRule` `password-policy.rules` config অনুযায়ী minimum length, character class, personal information, banned word এবং repeated/sequential pattern পরীক্ষা করে। User দিলে admin profile ও personal-info check প্রযোজ্য; user না দিলে global rule চলে এবং personal-info check বাদ যায়। Registration-এ `password_policy` string alias ব্যবহার করা যায়। Custom validation message lang file-এ দিন। Company name বা প্রচলিত দুর্বল শব্দ `rules.banned_words`-এ যোগ করুন। Birthdate/name/email/phone field-এর mapping `columns.*` থেকে আসে। Tinker example উপরের [Password rules](#1-password-rules) অংশে আছে।

#### ২. Password history

Default-এ history চালু এবং শেষ ৫টি password পুনঃব্যবহার নিষিদ্ধ। Password বদলালে trait পুরোনো hash `password_histories`-এ রাখে; `PasswordNotReusedRule` নতুন plain password-কে শেষ Nটি hash-এর সঙ্গে পরীক্ষা করে। Admin-এর জন্য `admin.history_count` প্রযোজ্য এবং কঠোরতর মানটি নেওয়া হয়। Programmatic check-এর জন্য `$user->hasUsedPassword(...)` ব্যবহার করুন।

#### ৩. Current-password confirmation

স্বেচ্ছায় password বদলাতে বর্তমান password জানা প্রমাণ করতে `CurrentPasswordRule` ব্যবহার করুন। Temporary password বা expired password-এর বাধ্যতামূলক change-এ config অনুযায়ী rule skip হতে পারে। Administrator অন্যের password reset করলে rule প্রয়োগ করবেন না। Forced flow-তে `current_password` field-কে নিঃশর্ত `required` করবেন না।

#### ৪. Password expiry

`expiry.enabled`, `days`, `grace_days` ও `auto_disable` দিয়ে নিয়ন্ত্রণ করুন। `password.expiry` middleware expired user-কে change page-এ পাঠায় বা JSON `403 password_expired` দেয়। Grace period পার হলে scheduler, command অথবা middleware account disable করতে পারে। `PasswordExpiryService` দিয়ে expired/disable-due পরীক্ষা এবং `ExpiredAccountSweeper` দিয়ে dry run বা sweep করা যায়। Service account expiry নয়, rotation schedule অনুসরণ করে।

#### ৫. Temporary password

Administrator account তৈরি বা reset করলে `TemporaryPasswordService::issueFor()` random policy-compliant password বানিয়ে approved channel-এ পাঠায়; password কখনও return করে না এবং প্রথম login-এ change বাধ্যতামূলক হয়। Company email অগ্রাধিকার পায়, email না থাকলে registered phone; insecure fallback নেই। Valid channel না থাকলে `NoSecureChannelException`, delivery ব্যর্থ হলে `DeliveryFailedException` এবং transaction rollback হয়। Custom WhatsApp/Slack channel-এর জন্য `PasswordDeliveryChannel` implement করুন। Test/seeding-এর জন্য শুধু generate করা যায়, কিন্তু production delivery flow-তে plain password log করবেন না।

**User তৈরির সময় স্বয়ংক্রিয়ভাবে (default-এ বন্ধ):** `temporary_password.auto_issue_on_create => true` দিলে `HasPasswordPolicy` ব্যবহারকারী model-এ নতুন user তৈরির সঙ্গে সঙ্গে temporary password issue ও deliver হয়। `create()`-এ দেওয়া password এটি প্রতিস্থাপন করে, তাই column বাধ্যতামূলক হলে যেকোনো placeholder দিন। Channel না থাকলে বা delivery ব্যর্থ হলে user তৈরি আটকায় না; error `report()` ও audit হয়, পরে `issueFor()` দিয়ে আবার পাঠানো যায়। কিছু user (যেমন নিজে registration করা) বাদ দিতে model-এ `shouldIssueTemporaryPassword()` override করুন।

#### ৬. Account lockout

Default tiered lockout consecutive failure-এর পরে ৫, ১০ ও ৩০ মিনিট; পরেরগুলো ১২০ মিনিট ও identity verification চাইতে পারে। একই account-এ এক IP থেকে ৬০ সেকেন্ডে ৫ failure হলে default-এ administrator unlock না করা পর্যন্ত permanent lock হয়। Login credential check-এর আগে `LoginGuard` ব্যবহার করতে হবে। UI-তে generic error দেখান; internal log-এ exception-এর `reason` ও `retryAfterSeconds` রাখা যায়। `LockoutService` state দেখা, manual lock ও verified unlock সমর্থন করে। CLI unlock নেই; service বা admin API ব্যবহার করুন।

#### ৭. Disable, enable ও compromised account

`AccountService::disable()` login block ও session শেষ করে। `enable()` account চালু করে কিন্তু password change বাধ্যতামূলক করে। `markCompromised()` password unusable করে, সব session/token শেষ করে, change force করে এবং `PasswordCompromised` event পাঠায়। Identity verify করার পরে temporary password issue করুন।

#### ৮. Session termination

Password বদলালে trait user-এর অন্য web session ও API token শেষ করে; যে session change করেছে সেটি চালু থাকে। `sessions.terminate_on_password_change = false` দিয়ে বন্ধ করা যায়। `SessionTerminator` সব session অথবা current session রেখে বাকিগুলো শেষ করতে পারে। এটি `session_version` বাড়ায়, database session পরিষ্কার করে এবং Sanctum/Passport token মুছে দেয়; route-এ `password.session_version` middleware থাকা জরুরি।

#### ৯. Password reset protection

`reset.restricted_roles`, `role_attribute` অথবা custom `role_resolver` দিয়ে BA/SO-এর মতো role-এর self-reset বন্ধ করুন। Forgot-password route-এ middleware বা `CanSelfResetPassword` rule দিন। স্বাধীন পরিচয় যাচাইয়ের জন্য `ResetIdentityVerifier` একবার ব্যবহারযোগ্য code company email বা phone-এ পাঠায়; default ১০ মিনিট মেয়াদ, ৫টি ভুল চেষ্টার পরে lock। সফল reset-এর পরে Laravel `PasswordReset` event পাঠালে audit ও password-reset notice হয়; notice-এ password থাকে না। `password-policy:check` broker link expiry সর্বোচ্চ ৬০ মিনিটের মধ্যে আছে কি না পরীক্ষা করে।

#### ১০. Authenticator-app MFA (TOTP)

Google/Microsoft Authenticator, Authy ইত্যাদির ৬-digit code দ্বিতীয় factor হিসেবে ব্যবহার করা যায়। এটি default-এ বন্ধ। Enable করলে scope অনুযায়ী প্রয়োজনীয় হয় এবং app না থাকা user setup page-এ যায়। Bundled route/view ব্যবহার করতে `totp.routes` চালু করে `password.mfa` middleware দিন; অথবা `TotpEnrollmentService` ও `MfaService` দিয়ে নিজস্ব UI বানান। Enrollment secret/URI দেখিয়ে code confirm করুন; recovery code মাত্র একবার দেখান। Challenge TOTP বা recovery code গ্রহণ করে এবং ভুল code lockout count বাড়ায়।

`password_policy_settings` table-এর `totp.enabled`, `scope`, `grace_days`, `issuer` config-কে override করে; command বা admin API দিয়ে audited change করা যায়। Code-এ policy pin করতে `totp.enabled` ও `totp.lock_to_config` দুটোই true করুন। Scope `all`, `admins` বা trusted network-এর বাইরে `remote`; admin-এর MFA সবসময় প্রয়োজন। Secret `APP_KEY` দিয়ে encrypted, recovery code keyed hash, replay blocked, সফল verify-তে session ID renew হয়। `APP_KEY` বদলালে পুরোনো secret পড়া যাবে না। Settings table unavailable হলে config fallback ব্যবহৃত হয়।

#### ১১. Custom MFA driver

SMS, email OTP বা push দরকার হলে `MfaDriver` implement করে `mfa.driver`-এ class দিন; custom driver built-in driver-এর আগে প্রাধান্য পায়। Admin সবসময়, `require_remote` হলে trusted network-এর বাইরের user, এবং `require_all` হলে সবাই MFA ব্যবহার করবে। Factor না থাকলে fail-closed হিসেবে access block হবে। External driver থাকলে built-in enrollment endpoint `404 mfa_external_driver` দেয়, কারণ enrollment host driver-এর দায়িত্ব। OTP single-use ও স্বল্পমেয়াদি রাখুন।

#### ১২. Admin account

`admin.roles` অথবা truthy `admin.flag_attribute` দিয়ে admin শনাক্ত হয়। Global ও admin config-এর মধ্যে কঠোরতর minimum length, expiry ও history মান প্রয়োগ হয়। Default example-এ ১৪+ character, ৬০ দিনের expiry ও ৫ password history আছে। `daily_email_domains`-এ থাকা সাধারণ-use email দিয়ে admin login করলে `password-policy:check` তা flag করে, যাতে privileged ও দৈনন্দিন account পৃথক রাখা যায়।

#### ১৩. Service account ও rotation

Bot/integration account-এর named owner, purpose ও rotation schedule থাকা দরকার এবং interactive login করা উচিত নয়। `ServiceAccountService` register, update, due list, notification, vault rotation ও remove সমর্থন করে। `knownBy`-তে যাদের user ID আছে, তাদের কাউকে offboard করলে account অবিলম্বে rotation-due হয়। Package secret রাখে বা return করে না; configured vault callback না থাকলে rotation প্রত্যাখ্যান করে এবং vault ব্যর্থ হলে database change rollback করে। `rotation-due` command দিয়ে list, notify বা rotate করুন।

#### ১৪. কর্মী offboarding

`password-policy:offboard` command অথবা `OffboardingService` একই দিনে account disable করে, সব session/token শেষ করে এবং ব্যক্তি যে service-account password জানতেন সেগুলো rotation-due করে। Returned collection-এর প্রতিটি account vault-এর মাধ্যমে rotate করুন।

#### ১৫. Audit log

Login, failure, lockout, password change/reset, MFA ও admin action `password_audit_logs`-এ লেখা হয়। `audit.redact_keys`-এর password, token, code, OTP ইত্যাদি secret redacted থাকে। পড়ার access default-এ denied; `view-password-audit-logs` Gate define করুন। Model দিয়ে query, `AuditLogger` দিয়ে custom entry এবং Artisan command দিয়ে filter করা যায়। Application log-এর জন্য `RedactSensitiveData` tap যোগ করুন; array পরিষ্কারে `Redactor::redact()` আছে।

#### ১৬. Unusual-login detection

নির্ধারিত সময়ে failure threshold পার হলে, নতুন IPv4 /24 বা IPv6 /48 network থেকে সফল login হলে, অথবা resolver থাকলে নতুন country থেকে login হলে alert হয়। প্রথম login শুধু baseline তৈরি করে। Alert audit হয়, configured recipient-কে email যায় এবং `UnusualLoginDetected` event dispatch হয়। Country check-এর জন্য নিজের `GeoResolver` দিন; package কোনো external geo service bundle করে না।

#### ১৭. নিরাপদ HTTPS transport

`password.secure` non-HTTPS request এবং query string-এ password/current_password-এর মতো secret প্রত্যাখ্যান করে। Default-এ কেবল `APP_ENV=production`-এ সক্রিয়; `tls.enforce` দিয়ে force on/off করা যায়। Login, password ও reset route-এ middleware দিন। Proxy/load balancer-এর পেছনে Laravel trusted proxy সঠিকভাবে configure করুন, যাতে `$request->secure()` যথার্থ ফল দেয়।

#### ১৮. Default-password scan

Go-live-এর আগে `defaults.passwords`-এ vendor/default password যোগ করে `password-policy:check-defaults` চালান। `--flag` matching user-কে password change-এ বাধ্য করে; `--user` একটি user পরীক্ষা করে। প্রতিটি candidate প্রতিটি user-এর hash-এর সঙ্গে যাচাই হওয়ায় বড় database-এ এটি ধীর—off-peak সময়ে চালান।

### JSON API

Mobile app, SPA ও service-এর জন্য একই feature HTTP-তে পাওয়া যায়। API default-এ বন্ধ; `api.enabled` config বা runtime setting চালু না করা পর্যন্ত route `404` দেয়। Default guard `sanctum`; Passport ব্যবহার করলে passport driver-এর guard দিন। Guard list দিলে ক্রমানুসারে চেষ্টা হয়। Database setting প্রতি request-এ config-কে override করে।

Admin endpoint-এর Gate default-এ সবাইকে deny করে। Manage users, service accounts, settings, compliance ও audit-এর Gate define করুন। Default-এ admin route expiry, forced-change ও MFA middleware-এর পেছনে থাকে। Prefix default `/api/password-policy`; error সাধারণত `message`/`error` অথবা Laravel validation `errors` format-এ আসে। Anonymous ও secret-checking endpoint আলাদা throttle ব্যবহার করে।

Endpoint group-গুলোর সারাংশ:

| Group | কাজ |
|---|---|
| `login/check`, `reset/*` | anonymous pre-login check ও one-time-code reset |
| `policy`, `password/*` | বর্তমান policy/status, validation ও password change |
| `mfa/*` | status, enrollment, challenge, verification ও recovery code |
| `admin/users/*` | state, known login, lock/unlock, disable/enable, compromise, temporary password, session termination, offboarding ও MFA reset |
| `admin/service-accounts/*` | list, register, update, remove, rotate ও notification |
| `admin/settings` | database override পরিচালনা |
| `admin/audit`, `admin/compliance/*` | audit query, self-test ও default-password scan |

সম্পূর্ণ method/path, request field, response, curl flow এবং mobile MFA example উপরের [Endpoints](#endpoints) ও [Examples](#examples) অংশে আছে। API token-এর MFA verification cache-এ token-ভিত্তিকভাবে default ১২ ঘণ্টা থাকে; বহু server-এ shared cache ব্যবহার করুন। Reset code user-dependent check-এর আগে spent হয়, তাই failed attempt-এর পরে নতুন code চাইতে হবে। Login action নিজে এবং Laravel reset-link flow এই API-এর অংশ নয়।

### Artisan command

| Command | উদ্দেশ্য |
|---|---|
| `password-policy:check` | hashing, hidden password, HTTPS, reset expiry, MFA, admin separation, SMS dependency ও enrollment self-test; CI/deploy-এ চালান |
| `password-policy:check-defaults` | পরিচিত default password খুঁজে flag করে |
| `password-policy:disable-expired` | grace period পার হওয়া account dry-run/disable করে |
| `password-policy:rotation-due` | overdue service account list, notify বা rotate করে |
| `password-policy:offboard` | কর্মীর account disable ও shared password rotation flag করে |
| `password-policy:totp` | authenticator policy enable/disable/status/scope/reset পরিচালনা করে |
| `password-policy:audit` | সাম্প্রতিক audit entry filter করে দেখায় |

### Event

- `AccountLocked`: account lock হলে `user`, `reason`, `level`, `minutes` দেয়।
- `PasswordCompromised`: `markCompromised()` চললে `user`, `reportedBy` দেয়।
- `UnusualLoginDetected`: repeated failure/new network/new country হলে `user`, `identifier`, `reasons`, `ip` দেয়।

Listener দিয়ে Slack/SOC alert বা নিজস্ব logging করা যায়। Package Laravel-এর `Login`, `Failed`, `Lockout` ও `PasswordReset` event-ও শোনে।

### কনফিগারেশন

সব option `config/password-policy.php`-এ inline documented। প্রধান group: `rules`, `expiry`, `history`, `lockout`, `temporary_password`, `reset`, `anomaly`, `tls`, `audit`, `mfa`, `totp`, `api`, `admin`, `service_accounts`, `defaults`, `sessions`, `columns`, `current_password`, `middleware`, `user_model`। Relaxed rule, custom column, role-based admin detection এবং feature off করার recipe উপরের [Configuration](#configuration) অংশে আছে। `tls.enforce = null` শুধু production-এ HTTPS enforce করে; সব environment-এ চালাতে true, বন্ধ করতে false দিন।

### ব্যবহারের আগে গুরুত্বপূর্ণ বিষয়

- **Shared cache:** IP burst, repeated failure ও API MFA state cache-এ থাকে। বহু server-এ Redis/database ব্যবহার করুন; `array`/`file` নয়।
- **Lockout wording:** policy-র কিছু শব্দের বাস্তবায়ন configurable interpretation। Default IP burst খুব কঠোর হতে পারে; প্রয়োজনে attempt বাড়ান।
- **MFA factor:** built-in TOTP বা custom driver চালু না থাকলে MFA-required user block হবে।
- **Self-reset disclosure:** restricted role-এর response account/role আছে বলে ইঙ্গিত দিতে পারে; unknown email স্বাভাবিক response পায়।
- **Synchronous delivery:** temporary password, reset notice ও alert inline পাঠানো হয়, queued নয়।
- **Admin default:** ১৪ character, ৬০-day expiry ও ৫-history একটি default assumption।
- **Code-এর বাইরে:** password share/লিখে রাখা, অন্য system-এ reuse, browser save এবং একই ব্যক্তির admin/daily password আলাদা রাখা package দিয়ে পুরোপুরি enforce করা যায় না।
- **`APP_KEY`:** TOTP secret এটি দিয়ে encrypted; অসতর্কভাবে rotate করবেন না।

### নীতি-সম্মতি

Status legend: ✅ package-এ সম্পূর্ণ · 🔌 host application wiring/implementation দরকার · 🛡 Laravel বাস্তবায়ন করে, package যাচাই বা সম্পূরক নিয়ন্ত্রণ দেয় · ➖ business process/package-এর বাইরের বিষয়। Clause 3.1–3.9-এর পূর্ণ requirement, status ও implementation mapping উপরের [Policy compliance](#policy-compliance) table-এ অপরিবর্তিতভাবে রাখা হয়েছে, যাতে audit reference ও clause number একটিই authoritative source থাকে। প্রধান wiring dependency হলো middleware, login guard, Gate, MFA driver, vault এবং trusted proxy; business form/approval ও human password আচরণ application package-এর বাইরে।

### পরীক্ষা, আপগ্রেড ও লাইসেন্স

`composer install` এবং `vendor/bin/phpunit` চালিয়ে test করুন। Suite Orchestra Testbench ব্যবহার করে; delivery, MFA ও Geo resolver-এর fake class `tests/Support`-এ example হিসেবে আছে। প্রতিটি update-এর পরে migration চালান। নতুন config option পেতে publish/merge করুন; `--force` existing edit overwrite করে, তাই আগে diff করুন। নতুন কঠোর default পরবর্তী password change-এ প্রযোজ্য—পুরোনো behavior রাখতে published config-এ পুরোনো মান স্পষ্টভাবে দিন। পরিবর্তনের তালিকা [CHANGELOG.md](CHANGELOG.md)-এ। License: MIT।
