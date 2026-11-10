<?php

namespace Mainul\PasswordPolicy\Support;

use Illuminate\Mail\Mailable;
use Illuminate\Support\Facades\Mail;

/**
 * Sends the package's mails either synchronously (default) or through the
 * queue, controlled by `password-policy.mail.queue`.
 */
class MailDispatcher
{
    /**
     * @param  string|array<int,string>  $to
     * @param  string  $type  temporary_password | text | unusual_login | service_account_due
     */
    public static function send(string|array $to, Mailable $mailable, string $type): void
    {
        if (! static::shouldQueue($type)) {
            Mail::to($to)->send($mailable);

            return;
        }

        $connection = config('password-policy.mail.queue.connection');
        $queue = config('password-policy.mail.queue.queue');

        if ($connection) {
            $mailable->onConnection($connection);
        }

        if ($queue) {
            $mailable->onQueue($queue);
        }

        Mail::to($to)->queue($mailable);
    }

    public static function shouldQueue(string $type): bool
    {
        $override = config("password-policy.mail.queue.types.{$type}");

        if ($override !== null) {
            return (bool) $override;
        }

        return (bool) config('password-policy.mail.queue.enabled', false);
    }
}
