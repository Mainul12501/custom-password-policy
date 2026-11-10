<?php

namespace Mainul\PasswordPolicy\Mail;

use Illuminate\Mail\Mailable;

/** Generic plain-text mail; unlike Mail::raw() it can be queued. */
class PlainTextMail extends Mailable
{
    public function __construct(protected string $body, string $subject)
    {
        $this->subject($subject);
    }

    public function build(): static
    {
        return $this->text('password-policy::mail.plain', ['body' => $this->body]);
    }
}
