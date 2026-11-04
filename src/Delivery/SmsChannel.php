<?php

namespace Mainul\PasswordPolicy\Delivery;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\PasswordDeliveryChannel;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Throwable;

/**
 * Fallback channel: the user's registered phone, via xenon/laravelbdsms
 * (Policy 3.1.3). The dependency is optional; without it this channel reports
 * that it cannot deliver.
 */
class SmsChannel implements PasswordDeliveryChannel
{
    public const FACADE = \Xenon\LaravelBDSms\Facades\SMS::class;

    public function name(): string
    {
        return 'sms';
    }

    public function canDeliverTo(Authenticatable $user): bool
    {
        return class_exists(static::FACADE) && $this->phoneOf($user) !== null;
    }

    public function send(Authenticatable $user, string $temporaryPassword): void
    {
        $this->sendText(
            $user,
            "Your temporary password is: {$temporaryPassword} . Change it at first login. Do not share it."
        );
    }

    public function sendText(Authenticatable $user, string $text, ?string $subject = null): void
    {
        $phone = $this->phoneOf($user);

        if (! class_exists(static::FACADE) || $phone === null) {
            throw new DeliveryFailedException('SMS delivery is unavailable (xenon/laravelbdsms missing or no phone number).');
        }

        $facade = static::FACADE;

        try {
            $facade::shoot($phone, $text);
        } catch (Throwable $e) {
            throw new DeliveryFailedException('Failed to send the SMS.', 0, $e);
        }
    }

    protected function phoneOf(Authenticatable $user): ?string
    {
        $phone = $user->{config('password-policy.columns.phone', 'phone')} ?? null;

        return is_string($phone) && trim($phone) !== '' ? trim($phone) : null;
    }
}
