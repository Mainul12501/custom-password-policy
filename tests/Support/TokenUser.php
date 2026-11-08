<?php

namespace Mainul\PasswordPolicy\Tests\Support;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Mainul\PasswordPolicy\Tests\User;

/**
 * A user shaped like Sanctum's HasApiTokens: a tokens() relation and
 * currentAccessToken(), without needing Sanctum installed.
 */
class TokenUser extends User
{
    protected $table = 'users';

    public ?TestToken $currentToken = null;

    public function tokens(): HasMany
    {
        return $this->hasMany(TestToken::class, 'user_id');
    }

    public function currentAccessToken(): ?TestToken
    {
        return $this->currentToken;
    }
}
