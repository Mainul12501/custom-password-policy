<?php

namespace Mainul\PasswordPolicy\Delivery;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\PasswordDeliveryChannel;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Mail\PlainTextMail;
use Mainul\PasswordPolicy\Mail\TemporaryPasswordMail;
use Mainul\PasswordPolicy\Support\MailDispatcher;
use Throwable;

/** Primary channel: the user's registered company email (Policy 3.1.3). */
class MailChannel implements PasswordDeliveryChannel
{
    public function name(): string
    {
        return 'mail';
    }

    public function canDeliverTo(Authenticatable $user): bool
    {
        $email = $this->emailOf($user);

        if (! is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return false;
        }

        $domains = array_map('strtolower', config('password-policy.temporary_password.company_email_domains', []));

        if ($domains === []) {
            return true;
        }

        return in_array(strtolower(substr(strrchr($email, '@'), 1)), $domains, true);
    }

    public function send(Authenticatable $user, string $temporaryPassword): void
    {
        try {
            MailDispatcher::send($this->emailOf($user), new TemporaryPasswordMail($temporaryPassword), 'temporary_password');
        } catch (Throwable $e) {
            // Deliberately do not include the password or the original message.
            throw new DeliveryFailedException('Failed to send the temporary password by email.', 0, $e);
        }
    }

    public function sendText(Authenticatable $user, string $text, ?string $subject = null): void
    {
        try {
            MailDispatcher::send($this->emailOf($user), new PlainTextMail($text, $subject ?? 'Security notice'), 'text');
        } catch (Throwable $e) {
            throw new DeliveryFailedException('Failed to send the message by email.', 0, $e);
        }
    }

    protected function emailOf(Authenticatable $user): mixed
    {
        return $user->{config('password-policy.columns.email', 'email')} ?? null;
    }
}
