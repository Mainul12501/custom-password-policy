<?php

namespace Mainul\PasswordPolicy\Mail;

use Illuminate\Mail\Mailable;

class TemporaryPasswordMail extends Mailable
{
    public function __construct(protected string $temporaryPassword)
    {
    }

    public function build(): static
    {
        $password = e($this->temporaryPassword);

        return $this
            ->subject((string) config('password-policy.temporary_password.mail_subject', 'Your temporary password'))
            ->html(
                '<p>An account has been created or reset for you.</p>'
                . "<p>Your temporary password is: <strong>{$password}</strong></p>"
                . '<p>You must change it immediately when you first sign in. '
                . 'Do not share it or write it down in an open location.</p>'
            );
    }
}
