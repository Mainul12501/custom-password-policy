<?php

namespace Mainul\PasswordPolicy\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\Eloquent\Model;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\SessionTerminator;

/** Feeds Laravel's Failed/Login events into the lockout counters (3.4.1). */
class TrackLoginFailures
{
    public function __construct(protected LockoutService $lockout)
    {
    }

    public function handleFailed(Failed $event): void
    {
        if ($event->user instanceof Model) {
            $this->lockout->recordFailure($event->user, app()->bound('request') ? request()->ip() : null);
        }
    }

    public function handleLogin(Login $event): void
    {
        if ($event->user instanceof Model) {
            $this->lockout->recordSuccess($event->user);
        }

        // A new login must pass MFA again.
        if (app()->bound('request')) {
            app(\Mainul\PasswordPolicy\Services\MfaService::class)->forget(request());
        }

        // Remember which session generation this login belongs to.
        if (app()->bound('request') && request()->hasSession()) {
            request()->session()->put(SessionTerminator::SESSION_KEY, (int) ($event->user->session_version ?? 0));
        }
    }
}
