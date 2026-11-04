<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;

class RecordingVault
{
    /** @var array<int,array{0:mixed,1:string}> */
    public static array $stored = [];

    public function __invoke(Authenticatable $user, string $secret): void
    {
        self::$stored[] = [$user->getAuthIdentifier(), $secret];
    }
}
