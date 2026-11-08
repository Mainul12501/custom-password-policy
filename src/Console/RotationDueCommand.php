<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Services\ServiceAccountService;
use Throwable;

class RotationDueCommand extends Command
{
    protected $signature = 'password-policy:rotation-due
        {--notify : Email the owners and notify_recipients}
        {--rotate : Rotate every due account now (needs a configured vault)}';

    protected $description = 'List service accounts whose password rotation is due';

    public function handle(ServiceAccountService $service): int
    {
        $due = $service->due();

        if ($due->isEmpty()) {
            $this->info('No service account rotations are due.');

            return self::SUCCESS;
        }

        $this->table(
            ['Account id', 'Owner', 'Purpose', 'Due since'],
            $due->map(fn ($a) => [$a->user_id, $a->owner, $a->purpose, $a->next_rotation_at])->all()
        );

        if ($this->option('notify')) {
            $this->notify($due, $service);
        }

        $failed = false;

        if ($this->option('rotate')) {
            $class = config('password-policy.user_model');

            foreach ($due as $account) {
                try {
                    $service->rotate($class::findOrFail($account->user_id));
                    $this->info("Rotated account [{$account->user_id}].");
                } catch (Throwable $e) {
                    $failed = true;
                    $this->error("Account [{$account->user_id}] not rotated: " . $e->getMessage());
                }
            }
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    protected function notify($due, ServiceAccountService $service): void
    {
        $count = $service->notifyDue($due);

        $count === 0
            ? $this->warn('No recipients to notify (owners are not emails and notify_recipients is empty).')
            : $this->info("Notified {$count} recipient(s).");
    }
}
