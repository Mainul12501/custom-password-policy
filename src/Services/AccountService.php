<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Mainul\PasswordPolicy\Events\PasswordCompromised;

/**
 * Account lifecycle actions: disable, re-enable and compromise response
 * (Policy 3.5.1, 3.7.5, 3.8.3).
 */
class AccountService
{
    public const REASON_PASSWORD_EXPIRED = 'password_expired';
    public const REASON_LEAVER = 'leaver';

    public function __construct(
        protected AuditLogger $audit,
        protected SessionTerminator $sessions,
    ) {
    }

    public function isDisabled(Authenticatable $user): bool
    {
        return ! empty($user->disabled_at ?? null);
    }

    /** Disable the account and end all its sessions. Idempotent. */
    public function disable(Model&Authenticatable $user, string $reason, Authenticatable|string|null $actor = null): void
    {
        if ($this->isDisabled($user)) {
            return;
        }

        $user->forceFill(['disabled_at' => now(), 'disabled_reason' => $reason])->saveQuietly();
        $this->sessions->terminate($user, false, 'account_disabled');

        $this->audit->log('account_disabled', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'reason' => $reason,
            'actor'  => $this->actorId($actor),
        ]);
    }

    /**
     * Re-enable the account. The user must change their password at the next
     * login, so a disabled-for-expiry user does not just carry on.
     */
    public function enable(Model&Authenticatable $user, Authenticatable|string|null $actor = null): void
    {
        $user->forceFill([
            'disabled_at'          => null,
            'disabled_reason'      => null,
            'must_change_password' => true,
        ])->saveQuietly();

        $this->audit->log('account_enabled', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'actor' => $this->actorId($actor),
        ]);
    }

    /**
     * A password compromise is confirmed: make the current password unusable,
     * require a reset and terminate every session (3.7.5). The user then
     * regains access through the password reset flow.
     */
    public function markCompromised(Model&Authenticatable $user, Authenticatable|string|null $actor = null): void
    {
        // Random value nobody knows. setTemporaryPassword keeps the forced
        // change flag and the old password goes to history.
        $user->setTemporaryPassword(Hash::make(Str::random(64)));
        $user->save();

        $this->sessions->terminate($user, false, 'compromise');

        $this->audit->log('forced_reset', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'actor' => $this->actorId($actor),
        ]);

        event(new PasswordCompromised($user, $this->actorId($actor)));
    }

    protected function actorId(Authenticatable|string|null $actor): ?string
    {
        return $actor instanceof Authenticatable ? (string) $actor->getAuthIdentifier() : $actor;
    }
}
