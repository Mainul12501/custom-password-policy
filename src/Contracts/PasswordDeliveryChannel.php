<?php

namespace Mainul\PasswordPolicy\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface PasswordDeliveryChannel
{
    /** Short channel name recorded in the audit log, e.g. "mail". */
    public function name(): string;

    /** Whether this channel can reach the user right now. */
    public function canDeliverTo(Authenticatable $user): bool;

    /**
     * Deliver the temporary password. Must throw DeliveryFailedException on
     * failure and must never log the password.
     */
    public function send(Authenticatable $user, string $temporaryPassword): void;

    /**
     * Deliver a short plain-text message (reset code, reset notice...). Must
     * throw DeliveryFailedException on failure and must never log the text.
     */
    public function sendText(Authenticatable $user, string $text, ?string $subject = null): void;
}
