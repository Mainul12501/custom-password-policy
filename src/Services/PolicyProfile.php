<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Effective password settings for a user: the global config, made stricter
 * for admin accounts (Policy 3.9.2).
 */
class PolicyProfile
{
    public function __construct(protected AccountClassifier $classifier)
    {
    }

    public function rules(?Authenticatable $user = null): array
    {
        $rules = config('password-policy.rules', []);

        if ($user && $this->classifier->isAdmin($user)) {
            $merged = array_merge($rules, (array) config('password-policy.admin.rules', []));

            // Admin settings may only tighten the policy, never loosen it.
            $merged['min_length'] = max((int) ($rules['min_length'] ?? 11), (int) ($merged['min_length'] ?? 0));
            $rules = $merged;
        }

        return $rules;
    }

    public function expiryDays(?Authenticatable $user = null): int
    {
        $days = (int) config('password-policy.expiry.days', 90);
        $admin = config('password-policy.admin.expiry_days');

        if ($user && $admin !== null && $this->classifier->isAdmin($user)) {
            // A disabled expiry (0) stays disabled; otherwise take the stricter value.
            return $days > 0 ? min($days, (int) $admin) : $days;
        }

        return $days;
    }

    public function historyCount(?Authenticatable $user = null): int
    {
        $count = (int) config('password-policy.history.max_reuse_count', 5);
        $admin = config('password-policy.admin.history_count');

        if ($user && $admin !== null && $count > 0 && $this->classifier->isAdmin($user)) {
            return max($count, (int) $admin);
        }

        return $count;
    }
}
