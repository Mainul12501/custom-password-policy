<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Mail;
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
            $this->notify($due);
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

    protected function notify($due): void
    {
        $lines = $due->map(fn ($a) => "- account {$a->user_id} (owner {$a->owner}): {$a->purpose}")->implode("\n");
        $recipients = array_filter((array) config('password-policy.service_accounts.notify_recipients', []));

        foreach ($due->pluck('owner') as $owner) {
            if (filter_var($owner, FILTER_VALIDATE_EMAIL)) {
                $recipients[] = $owner;
            }
        }

        $recipients = array_unique($recipients);

        if ($recipients === []) {
            $this->warn('No recipients to notify (owners are not emails and notify_recipients is empty).');

            return;
        }

        Mail::raw("Service account password rotation is due:\n{$lines}", fn ($m) => $m->to($recipients)->subject('Service account rotation due'));
        $this->info('Notified ' . count($recipients) . ' recipient(s).');
    }
}
