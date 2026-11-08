<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Mainul\PasswordPolicy\Mfa\TotpDriver;
use RuntimeException;
use Symfony\Component\HttpFoundation\IpUtils;
use Mainul\PasswordPolicy\Contracts\MfaDriver;

/**
 * Decides who needs MFA and tracks whether this session has passed it
 * (Policy 3.4.3, 3.4.4, 3.9.2).
 */
class MfaService
{
    public const SESSION_KEY = 'password_policy.mfa_user';

    public function __construct(
        protected AccountClassifier $classifier,
        protected AuditLogger $audit,
        protected SettingsRepository $settings,
        protected LockoutService $lockout,
    ) {
    }

    /** The built-in authenticator-app login is switched on. */
    public function totpEnabled(): bool
    {
        return (bool) $this->settings->get('totp.enabled', false);
    }

    protected function driverClass(): ?string
    {
        return config('password-policy.mfa.driver') ?: ($this->totpEnabled() ? TotpDriver::class : null);
    }

    public function hasDriver(): bool
    {
        return (bool) $this->driverClass();
    }

    public function driver(): MfaDriver
    {
        $class = $this->driverClass();

        if (! $class) {
            throw new RuntimeException('No MFA driver configured (password-policy.mfa.driver).');
        }

        return app($class);
    }

    /** Admins always; remote requests and everyone-mode when configured. */
    public function isRequired(Authenticatable $user, ?Request $request = null): bool
    {
        if ($this->classifier->isAdmin($user)) {
            return true;
        }

        if (config('password-policy.mfa.require_all', false)) {
            return true;
        }

        if ($this->totpEnabled() && $this->totpScopeMatches($user, $request)) {
            return true;
        }

        return config('password-policy.mfa.require_remote', true) && $this->isRemote($request);
    }

    protected function totpScopeMatches(Authenticatable $user, ?Request $request): bool
    {
        return match ($this->settings->get('totp.scope', 'all')) {
            'admins' => $this->classifier->isAdmin($user),
            'remote' => $this->isRemote($request),
            default  => true,
        };
    }

    /**
     * Users who have not enrolled may sign in for `totp.grace_days` after the
     * feature was switched on. Applies to the built-in driver only, and only
     * when the switch-on time was recorded.
     */
    public function inEnrollmentGrace(): bool
    {
        if (config('password-policy.mfa.driver') || ! $this->totpEnabled()) {
            return false;
        }

        $days = (int) $this->settings->get('totp.grace_days', 0);
        $since = $this->settings->get('totp.enabled_at');

        if ($days <= 0 || ! $since) {
            return false;
        }

        return \Illuminate\Support\Carbon::parse($since)->addDays($days)->isFuture();
    }

    /** Not from a known internal network. Unknown networks mean "cannot tell": not remote. */
    public function isRemote(?Request $request): bool
    {
        $networks = (array) config('password-policy.mfa.internal_networks', []);
        $ip = $request?->ip();

        if ($networks === [] || $ip === null) {
            return false;
        }

        return ! IpUtils::checkIp($ip, $networks);
    }

    public function isEnrolled(Authenticatable $user): bool
    {
        return $this->driver()->isEnrolled($user);
    }

    public function isVerified(Authenticatable $user, Request $request): bool
    {
        if ($request->hasSession()) {
            return (string) $request->session()->get(self::SESSION_KEY) === (string) $user->getAuthIdentifier();
        }

        $key = $this->tokenKey($user, $request);

        return $key !== null && Cache::has($key);
    }

    public function challenge(Authenticatable $user): void
    {
        $this->driver()->challenge($user);
        $this->audit->log('mfa_challenge', AuditLogger::OUTCOME_SUCCESS, $user);
    }

    /** Check a code and, if right, mark this session as having passed MFA. */
    public function verify(Authenticatable $user, string $code, Request $request): bool
    {
        // A locked account gets no more guesses at the code.
        if ($this->lockout->isLocked($user)) {
            $this->audit->log('mfa_verified', AuditLogger::OUTCOME_BLOCKED, $user, null, ['reason' => 'locked']);

            return false;
        }

        $ok = $this->driver()->isEnrolled($user) && $this->driver()->verify($user, $code);

        if ($ok) {
            $this->markVerified($user, $request);
            if ($user instanceof Model) {
                $this->lockout->recordSuccess($user);
            }
        } elseif ($user instanceof Model) {
            $this->lockout->recordFailure($user, $request->ip());
        }

        $this->audit->log('mfa_verified', $ok ? AuditLogger::OUTCOME_SUCCESS : AuditLogger::OUTCOME_FAILURE, $user);

        return $ok;
    }

    /**
     * Mark this session as having passed MFA and rotate the session id.
     * Requests without a session (API tokens) are remembered per token for
     * `mfa.token_ttl_minutes`; the cache must be shared between servers.
     */
    public function markVerified(Authenticatable $user, Request $request): void
    {
        if ($request->hasSession()) {
            $request->session()->regenerate();
            $request->session()->put(self::SESSION_KEY, $user->getAuthIdentifier());

            return;
        }

        if ($key = $this->tokenKey($user, $request)) {
            Cache::put($key, true, now()->addMinutes((int) config('password-policy.mfa.token_ttl_minutes', 720)));
        }
    }

    public function forget(Request $request, ?Authenticatable $user = null): void
    {
        if ($request->hasSession()) {
            $request->session()->forget(self::SESSION_KEY);

            return;
        }

        if ($user && ($key = $this->tokenKey($user, $request))) {
            Cache::forget($key);
        }
    }

    /** Cache key for a bearer token. The token itself is never stored. */
    protected function tokenKey(Authenticatable $user, Request $request): ?string
    {
        $token = $request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        return 'password-policy:mfa:' . $user->getAuthIdentifier() . ':' . hash('sha256', $token);
    }
}
