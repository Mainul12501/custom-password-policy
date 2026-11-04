<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Services\AccountService;

/**
 * Disables accounts whose password expired more than `grace_days` ago (3.5.1).
 * Users with no recorded password_changed_at are skipped on purpose.
 */
class DisableExpiredAccountsCommand extends Command
{
    protected $signature = 'password-policy:disable-expired {--dry-run : List accounts without disabling them}';

    protected $description = 'Disable accounts whose expired password was not changed within the grace period';

    public function handle(AccountService $accounts): int
    {
        if (! config('password-policy.expiry.enabled', true)
            || ! config('password-policy.expiry.auto_disable', true)
            || (int) config('password-policy.expiry.days', 90) <= 0) {
            $this->info('Automatic disabling is turned off.');

            return self::SUCCESS;
        }

        $days = (int) config('password-policy.expiry.days', 90) + (int) config('password-policy.expiry.grace_days', 1);
        $model = config('password-policy.user_model');
        $count = 0;

        $model::query()
            ->whereNull('disabled_at')
            // Service accounts rotate on a schedule instead of expiring.
            ->whereNotIn((new $model())->getKeyName(), \Mainul\PasswordPolicy\Models\ServiceAccount::query()->select('user_id'))
            ->whereNotNull('password_changed_at')
            ->where('password_changed_at', '<', now()->subDays($days))
            ->chunkById(100, function ($users) use ($accounts, &$count) {
                foreach ($users as $user) {
                    $count++;

                    if (! $this->option('dry-run')) {
                        $accounts->disable($user, AccountService::REASON_PASSWORD_EXPIRED);
                    }
                }
            });

        $this->info(($this->option('dry-run') ? 'Would disable ' : 'Disabled ') . "{$count} account(s).");

        return self::SUCCESS;
    }
}
