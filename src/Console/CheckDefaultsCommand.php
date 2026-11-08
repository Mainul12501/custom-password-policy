<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Services\DefaultPasswordScanner;

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

    public function handle(DefaultPasswordScanner $scanner): int
    {
        $found = $scanner->scan((bool) $this->option('flag'), $this->option('user'));

        if ($found === []) {
            $this->info('No account uses a known default password.');

            return self::SUCCESS;
        }

        $this->error(count($found) . ' account(s) use a default password' . ($this->option('flag') ? ' and were flagged for a forced change.' : '.'));
        $this->table(['Id', 'Email'], array_map(fn ($row) => [$row['id'], $row['email']], $found));

        return self::FAILURE;
    }
}
