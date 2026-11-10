<?php

namespace Mainul\PasswordPolicy\Listeners;

use Mainul\PasswordPolicy\Events\UnusualLoginDetected;
use Mainul\PasswordPolicy\Mail\PlainTextMail;
use Mainul\PasswordPolicy\Support\MailDispatcher;
use Throwable;

/** Default alert: an email to `anomaly.alert_recipients` (3.7.4). */
class SendUnusualLoginAlert
{
    public function handle(UnusualLoginDetected $event): void
    {
        $recipients = array_filter((array) config('password-policy.anomaly.alert_recipients', []));

        if ($recipients === []) {
            return;
        }

        $who = $event->user
            ? 'account #' . $event->user->getAuthIdentifier()
            : 'identifier "' . ($event->identifier ?? 'unknown') . '"';

        $body = "Unusual login activity for {$who}.\n"
            . 'Reasons: ' . implode(', ', $event->reasons) . "\n"
            . 'IP: ' . ($event->ip ?? 'unknown') . "\n"
            . 'Time: ' . now()->toDateTimeString() . ' ' . now()->timezoneName;

        try {
            MailDispatcher::send($recipients, new PlainTextMail($body, 'Unusual login activity'), 'unusual_login');
        } catch (Throwable $e) {
            report($e);
        }
    }
}
