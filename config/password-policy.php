<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Password Validation Rules
    |--------------------------------------------------------------------------
    |
    | Configure the requirements for password complexity. Each rule can be
    | independently enabled or disabled.
    |
    */
    'rules' => [
        'min_length'        => 11,
        'require_uppercase' => true,
        'require_lowercase' => true,
        'require_numeric'   => true,
        'require_special'   => true,

        // Reject passwords containing the user's own name, email name, phone
        // number or birthdate. Needs the user: PasswordPolicyRule::for($user).
        'forbid_personal_info' => true,

        // Reject passwords containing any of these words (case-insensitive),
        // e.g. the company name and common words.
        'banned_words' => ['password', 'welcome', 'admin', 'qwerty', 'letmein', 'changeme'],

        // Reject trivial patterns: 4+ repeated characters (aaaa) and
        // 4+ character sequences (1234, abcd).
        'forbid_patterns' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Expiry
    |--------------------------------------------------------------------------
    |
    | When enabled, users must change their password after the specified
    | number of days. Set 'enabled' to false or 'days' to 0 to disable.
    |
    | grace_days:   the account is disabled automatically when the password is
    |               still unchanged this many days after it expired (3.5.1).
    | auto_disable: schedule `password-policy:disable-expired` daily and let
    |               the account middleware disable on the spot.
    |
    */
    'expiry' => [
        'enabled'      => true,
        'days'         => 30,
        'grace_days'   => 1,
        'auto_disable' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Failed Login Lockout (Policy 3.4.1, 3.4.2)
    |--------------------------------------------------------------------------
    |
    | max_attempts:       consecutive failures that trigger a lockout cycle.
    | durations:          minutes locked for the 1st, 2nd, 3rd... cycle.
    | extended_minutes:   lock for every cycle after the listed ones. These
    |                     locks also require identity verification to unlock.
    | reset_after_hours:  the cycle counter resets after this long without a
    |                     failed attempt.
    | ip_burst:           `attempts` failures from one IP against one account
    |                     within `window_seconds` lock it permanently until an
    |                     administrator unlocks it.
    |
    */
    'lockout' => [
        'enabled'           => true,
        'max_attempts'      => 5,
        'durations'         => [5, 10, 30],
        'extended_minutes'  => 120,
        'reset_after_hours' => 24,
        'ip_burst'          => [
            'enabled'        => true,
            'attempts'       => 5,
            'window_seconds' => 60,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Forgotten Password and Reset (Policy 3.6.x)
    |--------------------------------------------------------------------------
    |
    | max_expire_minutes: `password-policy:check` fails when a password broker's
    |                     reset link lives longer than this (3.6.3).
    | notify:             tell the user whenever their password was reset (3.6.5).
    | restricted_roles:   roles that may NOT reset their own password and must
    |                     contact an administrator (3.6.6).
    | role_attribute:     user attribute holding the role (string or array).
    | role_resolver:      optional invokable class (receives the user, returns a
    |                     role or list of roles). Wins over role_attribute.
    | verifier:           class implementing ResetIdentityVerifier, used to prove
    |                     identity with a one-time code (3.6.2), mainly for users
    |                     who only have a phone.
    |
    */
    'reset' => [
        'max_expire_minutes'  => 60,
        'notify'              => true,
        'restricted_roles'    => ['BA', 'SO'], // set listed role names, which won't follow password rules
        'role_attribute'      => 'role',
        'role_resolver'       => null,
        'verifier'            => \Mainul\PasswordPolicy\Services\ResetCodeVerifier::class,
        'code_length'         => 6,
        'code_ttl_minutes'    => 10,
        'code_max_attempts'   => 5,
    ],

    /*
    |--------------------------------------------------------------------------
    | Unusual Login Detection (Policy 3.7.4)
    |--------------------------------------------------------------------------
    |
    | failure_threshold / window_minutes: alert when one account collects this
    |   many failed logins within the window.
    | new location: alert when a successful login comes from a network the user
    |   has not used before. The first login only sets the baseline.
    | geo_resolver: optional class with country(string $ip): ?string. Adds a
    |   "new country" check. No external service is bundled.
    | alert_recipients: addresses that receive the alert email. Every alert is
    |   also written to the audit log and dispatched as UnusualLoginDetected.
    |
    */
    'anomaly' => [
        'enabled'           => true,
        'failure_threshold' => 3,
        'window_minutes'    => 10,
        'ipv4_prefix'       => 24,
        'ipv6_prefix'       => 48,
        'geo_resolver'      => null,
        'alert_recipients'  => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Multi-Factor Authentication (Policy 3.4.3, 3.4.4, 3.9.2)
    |--------------------------------------------------------------------------
    |
    | The package enforces MFA; you supply the factor. Set `driver` to a class
    | implementing Contracts\MfaDriver (TOTP, SMS code, push...) and put the
    | `password.mfa` middleware on your authenticated routes.
    |
    | Always required: admin accounts (see the `admin` block).
    | require_remote:  also required when the request does not come from one of
    |                  `internal_networks` (CIDR list). With an empty list the
    |                  package cannot tell, so this check is skipped.
    | require_all:     require it for every user (standard accounts, 3.4.4).
    |
    | With no driver configured, users who need MFA are blocked (fail closed).
    |
    | Supported drivers (`driver`):
    |   null                                      Uses the bundled TotpDriver when
    |                                             `totp.enabled` is true; otherwise
    |                                             no factor (fail closed, see above).
    |   \Mainul\PasswordPolicy\Mfa\TotpDriver::class
    |                                             Authenticator app (Google / Microsoft
    |                                             Authenticator, Authy...) with
    |                                             recovery codes. The only driver
    |                                             bundled with the package.
    |   YourClass::class                          Any custom class implementing
    |                                             Contracts\MfaDriver (SMS code,
    |                                             push, email OTP...).
    |
    */
    'mfa' => [
        'driver'            => null,
        'require_remote'    => true,
        'internal_networks' => [],
        'require_all'       => false,
        // How long an API token stays "MFA verified" after a correct code.
        // Session-based requests stay verified for the life of the session.
        'token_ttl_minutes' => 720,
        'challenge_route'   => 'mfa.challenge',
        'enroll_route'      => 'mfa.enroll',
        'excluded_routes'   => ['mfa.challenge', 'mfa.verify', 'mfa.enroll', 'logout'],
        'excluded_paths'    => ['mfa', 'logout'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authenticator App Login (TOTP)
    |--------------------------------------------------------------------------
    |
    | An optional second step: after the password, the user types the 6-digit
    | code from Google Authenticator, Microsoft Authenticator, Authy, etc.
    | Off by default. When enabled it is required, and users who have not set
    | up an app are sent to the enrolment page.
    |
    | These are DEFAULTS. enabled, scope, grace_days and issuer can be
    | overridden at runtime in the `password_policy_settings` table
    | (`php artisan password-policy:totp --enable`). The database wins, except:
    |
    | lock_to_config: when true and `enabled` is true here, the database can
    |                 not switch the feature off. Keeps the policy in code.
    |
    | enabled:    turn the feature on. Uses TotpDriver unless `mfa.driver` names
    |             another driver.
    | scope:      who must use it: `all`, `admins` or `remote` (requests outside
    |             `mfa.internal_networks`).
    | grace_days: days after the feature was switched on during which users who
    |             have not enrolled may still sign in. 0 = enrol immediately.
    |             Counted from the `totp.enabled_at` setting, which
    |             `password-policy:totp --enable` records.
    | issuer:     the name shown in the authenticator app. Defaults to app name.
    | window:     steps of clock drift accepted either side (1 = +-30s).
    | routes:     load the bundled enrol/challenge routes and views. Leave false
    |             to build your own on TotpEnrollmentService.
    | route_middleware: middleware around the bundled routes.
    | recovery_codes: how many backup codes are issued.
    |
    */
    'totp' => [
        'enabled'          => false,
        'lock_to_config'   => false,
        'scope'            => 'all',
        'grace_days'       => 7,
        'issuer'           => null,
        'digits'           => 6,
        'period'           => 30,
        'algorithm'        => 'sha1',
        'window'           => 1,
        'recovery_codes'   => 8,
        'routes'           => false,
        'route_middleware' => ['web', 'auth'],
    ],

    /*
    |--------------------------------------------------------------------------
    | JSON API
    |--------------------------------------------------------------------------
    |
    | Every feature of the package is also available over HTTP for mobile apps,
    | SPAs and other services. The routes are always registered but answer 404
    | until `enabled` is true.
    |
    | enabled and guard are DEFAULTS. Both can be overridden at runtime in the
    | `password_policy_settings` table (keys `api.enabled`, `api.guard`), and
    | the database wins.
    |
    | guard:       the auth guard that identifies the caller. `sanctum` is the
    |              default. For Laravel Passport use the guard whose driver is
    |              `passport` (usually `api`). A list tries each guard in turn.
    | prefix:      URL prefix of every endpoint.
    | middleware:  middleware around every endpoint (before authentication).
    | throttle:    "attempts,minutes" for the unauthenticated endpoints and for
    |              the endpoints that check a secret.
    | admin_requires_mfa: put `password.mfa` on the /admin endpoints.
    | abilities:   Gate abilities protecting the /admin endpoints. Each denies
    |              everyone until your application defines it with Gate::define().
    |              Reading the audit log uses `audit.gate_ability`.
    |
    */
    'api' => [
        'enabled'    => false,
        'guard'      => 'sanctum',
        'prefix'     => 'api/password-policy',
        'middleware' => ['api'],
        'throttle'   => [
            'public'    => '6,1',
            'sensitive' => '10,1',
        ],
        'admin_requires_mfa' => true,
        'abilities'  => [
            'users'            => 'password-policy.manage-users',
            'service_accounts' => 'password-policy.manage-service-accounts',
            'settings'         => 'password-policy.manage-settings',
            'compliance'       => 'password-policy.view-compliance',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin Accounts (Policy 3.9.1, 3.9.2)
    |--------------------------------------------------------------------------
    |
    | Admins are users with one of `roles` (read from the same source as
    | reset.role_attribute / reset.role_resolver) or a truthy `flag_attribute`.
    | They get stricter password rules. Pass the user to get them:
    | PasswordPolicyRule::for($user).
    |
    | daily_email_domains: domains used for everyday mail. `password-policy:check`
    |   flags admins whose login email is on one of them (3.9.1).
    |
    */
    'admin' => [
        'roles'               => ['ADMIN', 'SUPER_ADMIN', 'SUPERADMIN'],
        'flag_attribute'      => 'is_admin',
        'rules'               => ['min_length' => 14],
        'expiry_days'         => 60,
        'history_count'       => 5,
        'daily_email_domains' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Service Accounts (Policy 3.9.3, 3.9.4)
    |--------------------------------------------------------------------------
    |
    | Service accounts need a named owner and a purpose, follow a rotation
    | schedule instead of password expiry, and never sign in interactively.
    |
    | vault: invokable class `(Authenticatable $user, string $secret): void`
    |        that stores a rotated secret in your vault. The package never
    |        keeps or returns the secret. Rotation is refused without it.
    | notify_recipients: addresses told about overdue rotations.
    |
    */
    'service_accounts' => [
        'default_rotation_days' => 90,
        'password_length'       => 32,
        'vault'                 => null,
        'notify_recipients'     => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Passwords (Policy 3.9.5)
    |--------------------------------------------------------------------------
    |
    | `password-policy:check-defaults` tests every user against this list.
    | Add vendor defaults for your own software.
    |
    */
    'defaults' => [
        'passwords' => [
            'password', 'Password1', 'Password@123', 'admin', 'admin123', 'Admin@123',
            'changeme', 'Changeme@123', 'welcome', 'Welcome@123', '12345678', 'qwerty123',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Termination (Policy 3.5.2, 3.8.4)
    |--------------------------------------------------------------------------
    |
    | When enabled, changing a password ends the user's other sessions and
    | API tokens. The session that made the change stays signed in.
    |
    */
    'sessions' => [
        'terminate_on_password_change' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Password History / Reuse Prevention
    |--------------------------------------------------------------------------
    |
    | When enabled, users cannot reuse their most recent N passwords.
    | max_reuse_count defines how many previous passwords to check against.
    |
    */
    'history' => [
        'enabled'         => true,
        'max_reuse_count' => 5,
    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Configure how the password expiry middleware behaves. Specify the
    | route to redirect web users and routes/paths to exclude from checks.
    |
    */
    'middleware' => [
        'password_change_route' => 'password.change',

        'excluded_routes' => [
            'password.change',
            'password.update',
            'logout',
        ],

        'excluded_paths' => [
            'password/change',
            'logout',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Columns
    |--------------------------------------------------------------------------
    |
    | Column names the package reads on the user model.
    |
    */
    'columns' => [
        'email' => 'email',
        'phone' => 'phone',
        'name'  => 'name',
        'birthdate' => 'date_of_birth',
    ],

    /*
    |--------------------------------------------------------------------------
    | Temporary Passwords (Policy 3.1.x)
    |--------------------------------------------------------------------------
    |
    | Temporary first passwords are generated randomly, delivered only through
    | an approved channel and must be changed at first login.
    |
    | delivery_order:        channels tried in order. The company email is the
    |                        primary channel; phone is used only when the user
    |                        has no usable email (3.1.3).
    | company_email_domains: when not empty, only emails on these domains
    |                        count as "company email".
    | auto_issue_on_create:  when true, every newly created user (model using
    |                        HasPasswordPolicy) automatically gets a random
    |                        temporary password delivered and must change it
    |                        at first login. Override shouldIssueTemporaryPassword()
    |                        on the model to skip some users. A delivery failure
    |                        never blocks the user creation; it is reported/audited.
    |
    */
    'temporary_password' => [
        'auto_issue_on_create'  => false,
        'length'                => 14,
        'delivery_order'        => ['mail', 'sms'],
        'channels'              => [
            'mail' => \Mainul\PasswordPolicy\Delivery\MailChannel::class,
            'sms'  => \Mainul\PasswordPolicy\Delivery\SmsChannel::class,
        ],
        'company_email_domains' => [],
        'mail_subject'          => 'Your temporary password',
    ],

    /*
    |--------------------------------------------------------------------------
    | Current Password Confirmation (Policy 3.5.4)
    |--------------------------------------------------------------------------
    |
    | CurrentPasswordRule is skipped for system-forced changes: the user has a
    | temporary password, or the password has expired.
    |
    */
    'current_password' => [
        'skip_when_forced'  => true,
        'skip_when_expired' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Secure Transport (Policy 3.3.x)
    |--------------------------------------------------------------------------
    |
    | enforce: null  = enforce only when APP_ENV is "production" (default)
    |          true  = always enforce
    |          false = never enforce
    |
    | Apply with the 'password.secure' middleware alias.
    |
    */
    'tls' => [
        'enforce'              => null,
        'forbidden_query_keys' => [
            'password', 'password_confirmation', 'current_password',
            'new_password', 'temporary_password', 'pass', 'pwd',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit Log (Policy 3.7.x)
    |--------------------------------------------------------------------------
    |
    | Login attempts, password changes and resets are recorded without ever
    | storing secrets. Reading the logs is gated by the ability below, which
    | denies everyone until your application defines it with Gate::define().
    |
    */
    'audit' => [
        'enabled'         => true,
        'gate_ability'    => 'view-password-audit-logs',
        'identifier_keys' => ['email', 'username', 'login'],
        'redact_keys'     => [
            'password', 'password_confirmation', 'current_password',
            'new_password', 'temporary_password', 'token', 'code',
            'reset_code', 'otp', 'secret', 'authorization',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The fully qualified class name of your User model. This is used by
    | the PasswordHistory model for its relationship.
    |
    */
    'user_model' => 'App\\Models\\User',

];
