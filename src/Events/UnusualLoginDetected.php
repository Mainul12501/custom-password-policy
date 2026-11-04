<?php

namespace Mainul\PasswordPolicy\Events;

use Illuminate\Contracts\Auth\Authenticatable;

class UnusualLoginDetected
{
    /**
     * @param  array<int,string>  $reasons  repeated_failures | new_network | new_country
     */
    public function __construct(
        public ?Authenticatable $user,
        public ?string $identifier,
        public array $reasons,
        public ?string $ip,
    ) {
    }
}
