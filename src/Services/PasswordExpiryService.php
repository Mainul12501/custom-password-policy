<?php

namespace Mainul\PasswordPolicy\Services;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;

class PasswordExpiryService
{
    public function isExpired(Authenticatable $user): bool
    {
        if (! config('password-policy.expiry.enabled', true)) {
            return false;
        }

        $days = config('password-policy.expiry.days', 90);

        if ($days <= 0) {
            return false;
        }

        $changedAt = $user->password_changed_at;

        if (is_null($changedAt)) {
            return true;
        }

        return Carbon::parse($changedAt)->addDays($days)->isPast();
    }
}
