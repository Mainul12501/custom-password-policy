<?php

namespace Mainul\PasswordPolicy\Exceptions;

use RuntimeException;

class NoSecureChannelException extends RuntimeException
{
    public static function forUser(mixed $user): self
    {
        $id = is_object($user) && method_exists($user, 'getAuthIdentifier') ? $user->getAuthIdentifier() : 'unknown';

        return new self("No approved delivery channel (company email or registered phone) is available for user [{$id}]. Temporary password was not issued.");
    }
}
