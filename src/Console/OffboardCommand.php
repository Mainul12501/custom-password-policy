<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Services\OffboardingService;

class OffboardCommand extends Command
{
    protected $signature = 'password-policy:offboard
        {user : User id or email}
        {--actor= : Who is performing the offboarding (recorded in the audit log)}';

    protected $description = 'Disable a leaver, end their sessions and flag shared/service passwords they knew for rotation';

    public function handle(OffboardingService $offboarding): int
    {
        $class = config('password-policy.user_model');
        $needle = $this->argument('user');

        $user = $class::query()
            ->where(config('password-policy.columns.email', 'email'), $needle)
            ->orWhere((new $class())->getKeyName(), $needle)
            ->first();

        if (! $user) {
            $this->error("No user found for [{$needle}].");

            return self::FAILURE;
        }

        $exposed = $offboarding->offboard($user, $this->option('actor'));

        $this->info("Account [{$user->getKey()}] disabled and all sessions ended.");

        if ($exposed->isEmpty()) {
            $this->line('No service or shared accounts list this user as knowing the password.');
        } else {
            $this->warn('Rotate these passwords now (marked as due):');
            $this->table(
                ['Account id', 'Owner', 'Purpose'],
                $exposed->map(fn ($a) => [$a->user_id, $a->owner, $a->purpose])->all()
            );
        }

        return self::SUCCESS;
    }
}
