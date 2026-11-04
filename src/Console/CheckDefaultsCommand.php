<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Services\AuditLogger;

/**
 * Pre-go-live gate (Policy 3.9.5): finds accounts that still use a known
 * default password. Exits non-zero when any are found, so CI can block.
 *
 * Each user is hashed against every default, so this is slow on large user
 * tables. Run it before launch, not on every request or deploy of a big system.
 */
class CheckDefaultsCommand extends Command
{
    protected $signature = 'password-policy:check-defaults
        {--flag : Force a password change for every account found}
        {--user= : Check a single user id}';

    protected $description = 'Find accounts still using a known default password';

    public function handle(AuditLogger $audit): int
    {
        $defaults = array_values(array_filter((array) config('password-policy.defaults.passwords', []), 'strlen'));
        $class = config('password-policy.user_model');
        $emailColumn = config('password-policy.columns.email', 'email');
        $found = [];

        $query = $class::query();
        if ($this->option('user')) {
            $query->whereKey($this->option('user'));
        }

        $query->chunkById(200, function ($users) use ($defaults, $audit, $emailColumn, &$found) {
            foreach ($users as $user) {
                foreach ($defaults as $candidate) {
                    if (! Hash::check($candidate, $user->password)) {
                        continue;
                    }

                    $found[] = [$user->getKey(), $user->{$emailColumn}];

                    if ($this->option('flag')) {
                        $user->forceFill(['must_change_password' => true])->saveQuietly();
                    }

                    // The matching password is deliberately not shown or logged.
                    $audit->log('default_password_found', AuditLogger::OUTCOME_ALERT, $user);

                    break;
                }
            }
        });

        if ($found === []) {
            $this->info('No account uses a known default password.');

            return self::SUCCESS;
        }

        $this->error(count($found) . ' account(s) use a default password' . ($this->option('flag') ? ' and were flagged for a forced change.' : '.'));
        $this->table(['Id', 'Email'], $found);

        return self::FAILURE;
    }
}
