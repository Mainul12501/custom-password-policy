<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\PasswordDeliveryChannel;

class FakeSmsChannel implements PasswordDeliveryChannel
{
    public static array $sent = [];

    public function name(): string
    {
        return 'sms';
    }

    public function canDeliverTo(Authenticatable $user): bool
    {
        return ! empty($user->phone);
    }

    public function send(Authenticatable $user, string $temporaryPassword): void
    {
        self::$sent[] = [$user->phone, $temporaryPassword];
    }

    public static array $texts = [];

    public function sendText(Authenticatable $user, string $text, ?string $subject = null): void
    {
        self::$texts[] = [$user->phone, $text];
    }
}
