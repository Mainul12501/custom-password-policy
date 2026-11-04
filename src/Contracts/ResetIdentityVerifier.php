<?php

namespace Mainul\PasswordPolicy\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Proves the identity of someone resetting a password, independently of the
 * reset link itself (Policy 3.6.2).
 */
interface ResetIdentityVerifier
{
    /**
     * Send a one-time code to the user's registered channel.
     *
     * @return string name of the channel used
     */
    public function issue(Authenticatable $user): string;

    /** Check a submitted code. A code works once and expires quickly. */
    public function verify(Authenticatable $user, string $code): bool;
}
