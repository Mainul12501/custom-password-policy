<?php

namespace Mainul\PasswordPolicy\Services;

use Mainul\PasswordPolicy\Models\ServiceAccount;

/**
 * Disables accounts whose password expired more than `grace_days` ago (3.5.1).
 * Users with no recorded password_changed_at are skipped on purpose.
 */
class ExpiredAccountSweeper
{
    public function __construct(protected AccountService $accounts)
    {
    }

    /** Whether automatic disabling is switched on. */
    public function enabled(): bool
    {
        return config('password-policy.expiry.enabled', true)
            && config('password-policy.expiry.auto_disable', true)
            && (int) config('password-policy.expiry.days', 90) > 0;
    }

    /**
     * @return int|null number of accounts disabled (or that would be), or null
     *                  when automatic disabling is off
     */
    public function sweep(bool $dryRun = false, ?string $actor = null): ?int
    {
        if (! $this->enabled()) {
            return null;
        }

        $days = (int) config('password-policy.expiry.days', 90) + (int) config('password-policy.expiry.grace_days', 1);
        $model = config('password-policy.user_model');
        $count = 0;

        $model::query()
            ->whereNull('disabled_at')
            // Service accounts rotate on a schedule instead of expiring.
            ->whereNotIn((new $model())->getKeyName(), ServiceAccount::query()->select('user_id'))
            ->whereNotNull('password_changed_at')
            ->where('password_changed_at', '<', now()->subDays($days))
            ->chunkById(100, function ($users) use ($dryRun, $actor, &$count) {
                foreach ($users as $user) {
                    $count++;

                    if (! $dryRun) {
                        $this->accounts->disable($user, AccountService::REASON_PASSWORD_EXPIRED, $actor);
                    }
                }
            });

        return $count;
    }
}
