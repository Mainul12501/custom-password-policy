<?php

namespace Mainul\PasswordPolicy\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\PasswordReset;
use Mainul\PasswordPolicy\Services\AuditLogger;

/**
 * Records login attempts and password resets in the audit log (3.7.1).
 * Only the account identifier is stored, never the submitted credentials.
 */
class AuditAuthenticationEvents
{
    public function __construct(protected AuditLogger $audit)
    {
    }

    public function handleLogin(Login $event): void
    {
        $this->audit->log('login_attempt', AuditLogger::OUTCOME_SUCCESS, $event->user, null, [
            'guard' => $event->guard,
        ]);
    }

    public function handleFailed(Failed $event): void
    {
        $this->audit->log(
            'login_attempt',
            AuditLogger::OUTCOME_FAILURE,
            $event->user,
            $this->identifierFrom($event->credentials),
            ['guard' => $event->guard],
        );
    }

    public function handleLockout(Lockout $event): void
    {
        $this->audit->log(
            'login_attempt',
            AuditLogger::OUTCOME_BLOCKED,
            null,
            $this->identifierFrom($event->request->all()),
            ['reason' => 'throttled'],
        );
    }

    public function handlePasswordReset(PasswordReset $event): void
    {
        $this->audit->log('password_reset_completed', AuditLogger::OUTCOME_SUCCESS, $event->user);
    }

    /** Fired by Laravel versions that emit PasswordResetLinkSent (3.7.1). */
    public function handleResetLinkSent(object $event): void
    {
        $this->audit->log('password_reset_requested', AuditLogger::OUTCOME_SUCCESS, $event->user ?? null);
    }

    protected function identifierFrom(array $input): ?string
    {
        foreach (config('password-policy.audit.identifier_keys', []) as $key) {
            if (isset($input[$key]) && is_string($input[$key])) {
                return mb_substr($input[$key], 0, 255);
            }
        }

        return null;
    }
}
