<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\PasswordDeliveryChannel;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;

/**
 * Picks the delivery channel for a temporary password: company email first,
 * registered phone only when email is not usable (Policy 3.1.3). There is no
 * insecure fallback; if nothing fits, an exception is thrown.
 */
class DeliveryResolver
{
    public function resolve(Authenticatable $user): PasswordDeliveryChannel
    {
        $channels = config('password-policy.temporary_password.channels', []);

        foreach (config('password-policy.temporary_password.delivery_order', ['mail', 'sms']) as $key) {
            if (! isset($channels[$key])) {
                continue;
            }

            /** @var PasswordDeliveryChannel $channel */
            $channel = app($channels[$key]);

            if ($channel->canDeliverTo($user)) {
                return $channel;
            }
        }

        throw NoSecureChannelException::forUser($user);
    }
}
