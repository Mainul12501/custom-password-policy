<?php

namespace Mainul\PasswordPolicy\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Mainul\PasswordPolicy\Services\DefaultPasswordScanner;
use Throwable;

/**
 * Whole-table default-password scan (3.9.5) run in the background, because it
 * hashes every user against every default. The result is kept in the cache.
 */
class ScanDefaultPasswords implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public const TTL_HOURS = 24;

    public int $timeout = 3600;

    public int $tries = 1;

    public function __construct(public string $scanId, public bool $flag = false)
    {
    }

    public static function cacheKey(string $scanId): string
    {
        return 'password-policy:scan:' . $scanId;
    }

    public function handle(DefaultPasswordScanner $scanner): void
    {
        $this->store(['status' => 'running']);

        try {
            $found = $scanner->scan($this->flag);
        } catch (Throwable $e) {
            report($e);
            $this->store(['status' => 'failed']);

            return;
        }

        $this->store(['status' => 'finished', 'flagged' => $this->flag, 'found' => $found]);
    }

    protected function store(array $state): void
    {
        Cache::put(self::cacheKey($this->scanId), $state + ['scan_id' => $this->scanId], now()->addHours(self::TTL_HOURS));
    }
}
