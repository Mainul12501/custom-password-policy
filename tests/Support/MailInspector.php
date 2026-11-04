<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Support\Facades\Mail;

/** Reads messages sent through Laravel's "array" mailer. */
trait MailInspector
{
    protected function useArrayMailer(): void
    {
        config()->set('mail.default', 'array');
        config()->set('mail.from', ['address' => 'noreply@example.com', 'name' => 'App']);
        Mail::purge('array');
    }

    /** @return array<int,object> */
    protected function sentMail(): array
    {
        return Mail::mailer('array')->getSymfonyTransport()->messages()->all();
    }

    protected function sentTextBodies(): array
    {
        return array_map(fn ($m) => (string) $m->getOriginalMessage()->getTextBody(), $this->sentMail());
    }
}
