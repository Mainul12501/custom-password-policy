<?php

namespace Mainul\PasswordPolicy\Logging;

use Mainul\PasswordPolicy\Support\Redactor;
use Monolog\LogRecord;

/**
 * Monolog tap that masks secrets in log context/extra (Policy 3.7.2).
 *
 * Enable per channel in config/logging.php:
 *
 *     'single' => [
 *         'driver' => 'single',
 *         'path'   => storage_path('logs/laravel.log'),
 *         'tap'    => [\Mainul\PasswordPolicy\Logging\RedactSensitiveData::class],
 *     ],
 */
class RedactSensitiveData
{
    public function __invoke($logger): void
    {
        foreach ($logger->getHandlers() as $handler) {
            $handler->pushProcessor($this->processor());
        }
    }

    public function processor(): callable
    {
        return fn (LogRecord $record): LogRecord => $record->with(
            context: Redactor::redact($record->context),
            extra: Redactor::redact($record->extra),
        );
    }
}
