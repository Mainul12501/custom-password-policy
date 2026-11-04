<?php

namespace Mainul\PasswordPolicy\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/** The second factor itself: TOTP, SMS code, push... supplied by the host. */
interface MfaDriver
{
    /** Whether the user has set up this factor. */
    public function isEnrolled(Authenticatable $user): bool;

    /**
     * Start a challenge where the factor needs one (send an SMS code, push
     * a prompt). Drivers such as TOTP can leave this empty.
     */
    public function challenge(Authenticatable $user): void;

    /** Check the code the user submitted. */
    public function verify(Authenticatable $user, string $code): bool;
}
