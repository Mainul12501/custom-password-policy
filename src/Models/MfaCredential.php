<?php

namespace Mainul\PasswordPolicy\Models;

use Illuminate\Database\Eloquent\Model;

/** A user's authenticator-app (TOTP) secret and recovery codes. */
class MfaCredential extends Model
{
    protected $table = 'mfa_credentials';

    protected $guarded = [];

    protected $hidden = ['secret', 'recovery_codes'];

    protected function casts(): array
    {
        return [
            'secret'         => 'encrypted',
            'confirmed_at'   => 'datetime',
            'last_used_step' => 'integer',
            'recovery_codes' => 'array',
        ];
    }

    public function isConfirmed(): bool
    {
        return $this->confirmed_at !== null;
    }
}
