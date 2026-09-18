<?php

namespace Mainul\PasswordPolicy\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;

trait HasPasswordPolicy
{
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
            }
        });
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
