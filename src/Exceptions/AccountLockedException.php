<?php

namespace Mainul\PasswordPolicy\Exceptions;

use RuntimeException;

/**
 * Thrown by LoginGuard when a sign-in must not be attempted. The message is
 * deliberately generic so it does not reveal why (lock vs. disabled).
 */
class AccountLockedException extends RuntimeException
{
    public function __construct(
        public readonly ?int $retryAfterSeconds = null,
        public readonly string $reason = 'locked',
    ) {
        parent::__construct('This account is currently unavailable. Try again later or contact the administrator.');
    }
}
