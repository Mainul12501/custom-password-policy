<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\MfaDriver;

class FakeMfaDriver implements MfaDriver
{
    /** @var array<int|string,bool> */
    public static array $enrolled = [];

    public static int $challenges = 0;

    public function isEnrolled(Authenticatable $user): bool
    {
        return self::$enrolled[$user->getAuthIdentifier()] ?? false;
    }

    public function challenge(Authenticatable $user): void
    {
        self::$challenges++;
    }

    public function verify(Authenticatable $user, string $code): bool
    {
        return $code === '123456';
    }
}
