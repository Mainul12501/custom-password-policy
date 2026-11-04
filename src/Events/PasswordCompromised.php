<?php

namespace Mainul\PasswordPolicy\Events;

use Illuminate\Contracts\Auth\Authenticatable;

class PasswordCompromised
{
    public function __construct(
        public Authenticatable $user,
        public ?string $reportedBy = null,
    ) {
    }
}
