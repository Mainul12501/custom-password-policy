<?php

namespace Mainul\PasswordPolicy\Events;

use Illuminate\Contracts\Auth\Authenticatable;

class AccountLocked
{
    public function __construct(
        public Authenticatable $user,
        public string $reason,
        public int $level,
        public ?int $minutes,
    ) {
    }
}
