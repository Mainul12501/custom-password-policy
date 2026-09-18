<?php

namespace Mainul\PasswordPolicy\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PasswordHistory extends Model
{
    protected $table = 'password_histories';

    protected $fillable = [
        'user_id',
        'password',
    ];

    protected $hidden = [
        'password',
    ];

    public function user(): BelongsTo
    {
        $userModel = config('password-policy.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel);
    }
}
