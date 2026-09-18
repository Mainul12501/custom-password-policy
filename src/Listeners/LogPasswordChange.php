<?php

namespace Mainul\PasswordPolicy\Listeners;

use Illuminate\Auth\Events\PasswordReset;

class LogPasswordChange
{
    public function handlePasswordReset(PasswordReset $event): void
    {
        $user = $event->user;

        if (is_null($user->password_changed_at) || ! $user->wasChanged('password_changed_at')) {
            $user->password_changed_at = now();
            $user->saveQuietly();
        }
    }
}
