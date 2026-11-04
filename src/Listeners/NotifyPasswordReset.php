<?php

namespace Mainul\PasswordPolicy\Listeners;

use Illuminate\Auth\Events\PasswordReset;
use Mainul\PasswordPolicy\Services\AuditLogger;
use Mainul\PasswordPolicy\Services\DeliveryResolver;
use Throwable;

/**
 * Tells the user their password was reset so an unauthorised reset can be
 * reported at once (Policy 3.6.5). The message never contains a password. A
 * delivery problem is audited and reported, but never undoes the reset.
 */
class NotifyPasswordReset
{
    public function __construct(
        protected DeliveryResolver $resolver,
        protected AuditLogger $audit,
    ) {
    }

    public function handle(PasswordReset $event): void
    {
        if (! config('password-policy.reset.notify', true)) {
            return;
        }

        $user = $event->user;
        $ip = app()->bound('request') ? request()->ip() : null;

        try {
            $channel = $this->resolver->resolve($user);

            $channel->sendText(
                $user,
                'Your password was reset on ' . now()->toDayDateTimeString() . ' (' . now()->timezoneName . ')'
                    . ($ip ? " from IP {$ip}" : '')
                    . '. If this was not you, report it to IT Security immediately.',
                'Your password was reset'
            );

            $this->audit->log('reset_notification', AuditLogger::OUTCOME_SUCCESS, $user, null, ['channel' => $channel->name()]);
        } catch (Throwable $e) {
            report($e);
            $this->audit->log('reset_notification', AuditLogger::OUTCOME_FAILURE, $user, null, [
                'error' => class_basename($e),
            ]);
        }
    }
}
