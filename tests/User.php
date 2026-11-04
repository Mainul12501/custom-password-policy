<?php

namespace Mainul\PasswordPolicy\Tests;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Mainul\PasswordPolicy\Traits\HasPasswordPolicy;

class User extends Authenticatable
{
    use HasPasswordPolicy;

    protected $guarded = [];

    protected $hidden = ['password', 'remember_token'];

    protected function casts(): array
    {
        return [
            'password_changed_at' => 'datetime',
        ];
    }
}
