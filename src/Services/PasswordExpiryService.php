<?php

namespace Mainul\PasswordPolicy\Services;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;

class PasswordExpiryService
{
    protected PolicyProfile $profile;

    protected AccountClassifier $classifier;

    public function __construct(?PolicyProfile $profile = null, ?AccountClassifier $classifier = null)
    {
        $this->profile = $profile ?? app(PolicyProfile::class);
        $this->classifier = $classifier ?? app(AccountClassifier::class);
    }

    public function isExpired(Authenticatable $user): bool
    {
        if (! config('password-policy.expiry.enabled', true)) {
            return false;
        }

        // Service accounts follow a rotation schedule, not password expiry.
        if ($this->classifier->isServiceAccount($user)) {
            return false;
        }

        $days = $this->profile->expiryDays($user);

        if ($days <= 0) {
            return false;
        }

        $changedAt = $user->password_changed_at;

        if (is_null($changedAt)) {
            return true;
        }

        return Carbon::parse($changedAt)->addDays($days)->isPast();
    }

    /**
     * True once the password is still unchanged `grace_days` after it expired
     * (3.5.1). A user with no recorded change date is never auto-disabled, so
     * enabling this feature cannot lock out accounts that predate the package.
     */
    public function isDisableDue(Authenticatable $user): bool
    {
        if (! config('password-policy.expiry.enabled', true)
            || ! config('password-policy.expiry.auto_disable', true)) {
            return false;
        }

        if ($this->classifier->isServiceAccount($user)) {
            return false;
        }

        $days = $this->profile->expiryDays($user);
        $changedAt = $user->password_changed_at ?? null;

        if ($days <= 0 || is_null($changedAt)) {
            return false;
        }

        $grace = (int) config('password-policy.expiry.grace_days', 1);

        return Carbon::parse($changedAt)->addDays($days + $grace)->isPast();
    }
}
