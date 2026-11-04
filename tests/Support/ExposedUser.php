<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Mainul\PasswordPolicy\Tests\User;

class ExposedUser extends User
{
    protected $hidden = [];
}
