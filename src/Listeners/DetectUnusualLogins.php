<?php

namespace Mainul\PasswordPolicy\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Mainul\PasswordPolicy\Services\AnomalyDetector;
use Throwable;

/** Feeds Laravel's Failed/Login events into the anomaly detector (3.7.4). */
class DetectUnusualLogins
{
    public function __construct(protected AnomalyDetector $detector)
    {
    }

    public function handleFailed(Failed $event): void
    {
        try {
            $this->detector->inspectFailure($event->user, $this->identifierFrom($event->credentials), $this->ip());
        } catch (Throwable $e) {
            report($e);
        }
    }

    public function handleLogin(Login $event): void
    {
        try {
            $this->detector->inspectLogin($event->user, $this->ip());
        } catch (Throwable $e) {
            report($e);
        }
    }

    protected function ip(): ?string
    {
        return app()->bound('request') ? request()->ip() : null;
    }

    protected function identifierFrom(array $credentials): ?string
    {
        foreach (config('password-policy.audit.identifier_keys', []) as $key) {
            if (isset($credentials[$key]) && is_string($credentials[$key])) {
                return $credentials[$key];
            }
        }

        return null;
    }
}
