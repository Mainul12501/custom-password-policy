<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Database\Eloquent\Model;

class TestToken extends Model
{
    protected $table = 'test_tokens';

    public $timestamps = false;

    protected $guarded = [];
}
