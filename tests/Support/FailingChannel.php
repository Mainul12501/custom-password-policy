<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\PasswordDeliveryChannel;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;

class FailingChannel implements PasswordDeliveryChannel
{
    public function name(): string
    {
        return 'mail';
    }

    public function canDeliverTo(Authenticatable $user): bool
    {
        return true;
    }

    public function send(Authenticatable $user, string $temporaryPassword): void
    {
        throw new DeliveryFailedException('boom');
    }

    public function sendText(Authenticatable $user, string $text, ?string $subject = null): void
    {
        throw new DeliveryFailedException('boom');
    }
}
