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
        'min_length'        => 8,
        'require_uppercase' => true,
        'require_lowercase' => true,
        'require_numeric'   => true,
        'require_special'   => true,
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
        'days'         => 90,
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
        'restricted_roles'    => ['BA', 'SO'],
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
    */
    'mfa' => [
        'driver'            => null,
        'require_remote'    => true,
        'internal_networks' => [],
        'require_all'       => false,
        'challenge_route'   => 'mfa.challenge',
        'enroll_route'      => 'mfa.enroll',
        'excluded_routes'   => ['mfa.challenge', 'mfa.verify', 'mfa.enroll', 'logout'],
        'excluded_paths'    => ['mfa', 'logout'],
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
        'max_reuse_count' => 3,
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
    |
    */
    'temporary_password' => [
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
