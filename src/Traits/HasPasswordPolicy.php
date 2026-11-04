<?php

namespace Mainul\PasswordPolicy\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Services\AuditLogger;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;
use Mainul\PasswordPolicy\Services\SessionTerminator;

trait HasPasswordPolicy
{
    /** Set by setTemporaryPassword() so the next save keeps the forced-change flag. */
    protected bool $passwordIsTemporary = false;

    public static function bootHasPasswordPolicy(): void
    {
        static::updating(function ($user) {
            if ($user->isDirty('password')) {
                $originalPassword = $user->getOriginal('password');

                if ($originalPassword) {
                    PasswordHistory::create([
                        'user_id'  => $user->id,
                        'password' => $originalPassword,
                    ]);
                }

                $user->password_changed_at = now();

                // A real change ends the "temporary password" state (3.1.6),
                // unless this save is itself issuing a temporary password.
                if ($user->passwordIsTemporary) {
                    $user->must_change_password = true;
                    $user->passwordIsTemporary = false;
                } else {
                    $user->must_change_password = false;
                }
            }
        });

        static::updated(function ($user) {
            if ($user->wasChanged('password')) {
                app(AuditLogger::class)->log('password_changed', AuditLogger::OUTCOME_SUCCESS, $user);

                // The old password must stop working everywhere (3.5.2).
                if (config('password-policy.sessions.terminate_on_password_change', true)) {
                    try {
                        app(SessionTerminator::class)->terminate($user, true, 'password_changed');
                    } catch (\Throwable $e) {
                        report($e);
                    }
                }
            }
        });
    }

    /**
     * Assign an already-hashed temporary password and require a change at the
     * next login. Call save() afterwards.
     */
    public function setTemporaryPassword(string $hashedPassword): static
    {
        $this->password = $hashedPassword;
        $this->passwordIsTemporary = true;

        return $this;
    }

    public function mustChangePassword(): bool
    {
        return (bool) ($this->must_change_password ?? false);
    }

    public function passwordHistories(): HasMany
    {
        return $this->hasMany(PasswordHistory::class);
    }

    public function passwordExpired(): bool
    {
        return app(PasswordExpiryService::class)->isExpired($this);
    }

    public function hasUsedPassword(string $plainPassword): bool
    {
        return app(PasswordHistoryService::class)->hasBeenUsed($this, $plainPassword);
    }
}
