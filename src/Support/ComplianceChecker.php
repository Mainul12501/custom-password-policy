<?php

namespace Mainul\PasswordPolicy\Support;

/**
 * Static checks behind `php artisan password-policy:check`.
 * Each check returns [label, status, detail] where status is pass|warn|fail.
 */
class ComplianceChecker
{
    /** @return array<int,array{0:string,1:string,2:string}> */
    public function run(): array
    {
        return [
            $this->hashingDriver(),
            $this->hiddenPassword(),
            $this->transport(),
            $this->smsDependency(),
            $this->resetLinkExpiry(),
            $this->mfaConfigured(),
            $this->totpEnrollment(),
            $this->adminSeparation(),
        ];
    }

    /** 3.2.2: only strong one-way hashing. */
    public function hashingDriver(): array
    {
        $driver = config('hashing.driver', 'bcrypt');

        return in_array($driver, ['bcrypt', 'argon', 'argon2id'], true)
            ? ['Hashing driver (3.2.2)', 'pass', $driver]
            : ['Hashing driver (3.2.2)', 'fail', "'{$driver}' is not an approved one-way algorithm (use bcrypt or argon2)."];
    }

    /** 3.2.4: password is hidden when the user model is serialized. */
    public function hiddenPassword(): array
    {
        $class = config('password-policy.user_model');

        if (! is_string($class) || ! class_exists($class)) {
            return ['Password hidden on user model (3.2.4)', 'warn', 'user_model is not set to an existing class.'];
        }

        $hidden = (new $class())->getHidden();

        return in_array('password', $hidden, true)
            ? ['Password hidden on user model (3.2.4)', 'pass', $class]
            : ['Password hidden on user model (3.2.4)', 'fail', "{$class} does not list 'password' in \$hidden."];
    }

    /** 3.3.1: HTTPS enforcement in production. */
    public function transport(): array
    {
        $enforce = config('password-policy.tls.enforce');
        $production = app()->environment('production');
        $active = $enforce === null ? $production : (bool) $enforce;

        if ($production && ! $active) {
            return ['Secure transport (3.3.1)', 'fail', 'Running in production but tls.enforce is disabled.'];
        }

        return ['Secure transport (3.3.1)', 'pass', $active
            ? 'HTTPS enforced (add the password.secure middleware to your routes)'
            : 'Not enforced outside production'];
    }

    /** 3.6.3: reset links must expire within a short window. */
    public function resetLinkExpiry(): array
    {
        $max = (int) config('password-policy.reset.max_expire_minutes', 60);
        $tooLong = [];

        foreach ((array) config('auth.passwords', []) as $broker => $settings) {
            $expire = (int) ($settings['expire'] ?? 60);

            if ($expire > $max) {
                $tooLong[] = "{$broker} ({$expire} min)";
            }
        }

        return $tooLong === []
            ? ['Reset link expiry (3.6.3)', 'pass', "all password brokers expire within {$max} minutes"]
            : ['Reset link expiry (3.6.3)', 'fail', "reset links live longer than {$max} minutes: " . implode(', ', $tooLong)];
    }

    /** 3.4.3 / 3.9.2: an MFA driver must exist or admins are locked out (fail closed). */
    public function mfaConfigured(): array
    {
        $driver = config('password-policy.mfa.driver');

        if (! $driver && app(\Mainul\PasswordPolicy\Services\MfaService::class)->totpEnabled()) {
            return ['MFA driver (3.4.3, 3.9.2)', 'pass', 'Built-in authenticator app (TOTP)'];
        }

        if (! $driver) {
            return ['MFA driver (3.4.3, 3.9.2)', 'warn', 'No driver configured: users who need MFA will be blocked by password.mfa.'];
        }

        return class_exists($driver) && is_subclass_of($driver, \Mainul\PasswordPolicy\Contracts\MfaDriver::class)
            ? ['MFA driver (3.4.3, 3.9.2)', 'pass', $driver]
            : ['MFA driver (3.4.3, 3.9.2)', 'fail', "{$driver} does not implement Contracts\\MfaDriver."];
    }

    /** Authenticator app: how many users still have to enrol. */
    public function totpEnrollment(): array
    {
        $label = 'Authenticator app enrolment';

        if (! app(\Mainul\PasswordPolicy\Services\MfaService::class)->totpEnabled()) {
            return [$label, 'pass', 'Authenticator app login is off.'];
        }

        $class = config('password-policy.user_model');

        if (! is_string($class) || ! class_exists($class)) {
            return [$label, 'warn', 'user_model is not set to an existing class.'];
        }

        $total = $class::query()->count();
        $enrolled = \Mainul\PasswordPolicy\Models\MfaCredential::whereNotNull('confirmed_at')->count();
        $missing = max(0, $total - $enrolled);

        return $missing === 0
            ? [$label, 'pass', "All {$total} users have set up an authenticator app."]
            : [$label, 'warn', "{$missing} of {$total} users have not set up an authenticator app."];
    }

    /** 3.9.1: admin accounts must not use an everyday mailbox as their login. */
    public function adminSeparation(): array
    {
        $domains = array_map('strtolower', (array) config('password-policy.admin.daily_email_domains', []));
        $label = 'Admin account separation (3.9.1)';

        if ($domains === []) {
            return [$label, 'warn', 'admin.daily_email_domains is empty, so shared mailboxes cannot be detected.'];
        }

        $class = config('password-policy.user_model');

        if (! is_string($class) || ! class_exists($class)) {
            return [$label, 'warn', 'user_model is not set to an existing class.'];
        }

        $classifier = app(\Mainul\PasswordPolicy\Services\AccountClassifier::class);
        $column = config('password-policy.columns.email', 'email');
        $offenders = [];

        $class::query()->chunkById(500, function ($users) use ($classifier, $domains, $column, &$offenders) {
            foreach ($users as $user) {
                $email = strtolower((string) $user->{$column});
                $domain = substr(strrchr($email, '@') ?: '', 1);

                if ($domain !== '' && in_array($domain, $domains, true) && $classifier->isAdmin($user)) {
                    $offenders[] = $user->getKey();
                }
            }
        });

        return $offenders === []
            ? [$label, 'pass', 'no admin logs in with an everyday mailbox']
            : [$label, 'fail', 'admin accounts on an everyday mail domain, ids: ' . implode(', ', array_slice($offenders, 0, 10))];
    }

    /** 3.1.3: SMS fallback availability. */
    public function smsDependency(): array
    {
        return class_exists(\Mainul\PasswordPolicy\Delivery\SmsChannel::FACADE)
            ? ['SMS delivery (3.1.3)', 'pass', 'xenon/laravelbdsms installed']
            : ['SMS delivery (3.1.3)', 'warn', 'xenon/laravelbdsms not installed; users without a company email cannot receive temporary passwords.'];
    }
}
