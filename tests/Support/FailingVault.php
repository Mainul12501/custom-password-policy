<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use RuntimeException;

class FailingVault
{
    public function __invoke(Authenticatable $user, string $secret): void
    {
        throw new RuntimeException('vault unreachable');
    }
}
