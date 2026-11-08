<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Services\ExpiredAccountSweeper;

/**
 * Disables accounts whose password expired more than `grace_days` ago (3.5.1).
 * Users with no recorded password_changed_at are skipped on purpose.
 */
class DisableExpiredAccountsCommand extends Command
{
    protected $signature = 'password-policy:disable-expired {--dry-run : List accounts without disabling them}';

    protected $description = 'Disable accounts whose expired password was not changed within the grace period';

    public function handle(ExpiredAccountSweeper $sweeper): int
    {
        $count = $sweeper->sweep((bool) $this->option('dry-run'));

        if ($count === null) {
            $this->info('Automatic disabling is turned off.');

            return self::SUCCESS;
        }

        $this->info(($this->option('dry-run') ? 'Would disable ' : 'Disabled ') . "{$count} account(s).");

        return self::SUCCESS;
    }
}
