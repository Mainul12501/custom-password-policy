<?php

namespace Mainul\PasswordPolicy\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Services\AuditLogger;
use Mainul\PasswordPolicy\Services\TemporaryPasswordService;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;
use Mainul\PasswordPolicy\Services\SessionTerminator;

trait HasPasswordPolicy
{
    /** Set by setTemporaryPassword() so the next save keeps the forced-change flag. */
    protected bool $passwordIsTemporary = false;

    public static function bootHasPasswordPolicy(): void
    {
        // Optional: issue and deliver a temporary password to every new user.
        static::created(function ($user) {
            if (! config('password-policy.temporary_password.auto_issue_on_create', false)
                || ! $user->shouldIssueTemporaryPassword()) {
                return;
            }

            try {
                app(TemporaryPasswordService::class)->issueFor($user);
            } catch (NoSecureChannelException|DeliveryFailedException $e) {
                // The account stays created; the failure is already audited.
                // An administrator can re-issue once a channel is available.
                report($e);
            }
        });

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

    /**
     * Whether a newly created user should get an automatic temporary password
     * (only consulted when `temporary_password.auto_issue_on_create` is on).
     * Override on your model to skip some users, e.g. self-registered ones.
     */
    public function shouldIssueTemporaryPassword(): bool
    {
        return true;
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
