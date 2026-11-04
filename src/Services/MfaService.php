<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
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
    ) {
    }

    public function hasDriver(): bool
    {
        return (bool) config('password-policy.mfa.driver');
    }

    public function driver(): MfaDriver
    {
        $class = config('password-policy.mfa.driver');

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

        return config('password-policy.mfa.require_remote', true) && $this->isRemote($request);
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
        return $request->hasSession()
            && (string) $request->session()->get(self::SESSION_KEY) === (string) $user->getAuthIdentifier();
    }

    public function challenge(Authenticatable $user): void
    {
        $this->driver()->challenge($user);
        $this->audit->log('mfa_challenge', AuditLogger::OUTCOME_SUCCESS, $user);
    }

    /** Check a code and, if right, mark this session as having passed MFA. */
    public function verify(Authenticatable $user, string $code, Request $request): bool
    {
        $ok = $this->driver()->isEnrolled($user) && $this->driver()->verify($user, $code);

        if ($ok && $request->hasSession()) {
            $request->session()->put(self::SESSION_KEY, $user->getAuthIdentifier());
        }

        $this->audit->log('mfa_verified', $ok ? AuditLogger::OUTCOME_SUCCESS : AuditLogger::OUTCOME_FAILURE, $user);

        return $ok;
    }

    public function forget(Request $request): void
    {
        if ($request->hasSession()) {
            $request->session()->forget(self::SESSION_KEY);
        }
    }
}
