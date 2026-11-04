<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Support\ComplianceChecker;

class CheckCommand extends Command
{
    protected $signature = 'password-policy:check';

    protected $description = 'Check this installation against the password architecture policy';

    public function handle(ComplianceChecker $checker): int
    {
        $failed = false;

        foreach ($checker->run() as [$label, $status, $detail]) {
            $failed = $failed || $status === 'fail';
            $line = sprintf('[%s] %s: %s', strtoupper($status), $label, $detail);

            match ($status) {
                'pass'  => $this->info($line),
                'warn'  => $this->warn($line),
                default => $this->error($line),
            };
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }
}
