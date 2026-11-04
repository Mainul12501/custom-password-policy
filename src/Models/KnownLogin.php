<?php

namespace Mainul\PasswordPolicy\Models;

use Illuminate\Database\Eloquent\Model;

class KnownLogin extends Model
{
    public $timestamps = false;

    protected $table = 'password_known_logins';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at'  => 'datetime',
        ];
    }
}
