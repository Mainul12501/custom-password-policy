<?php

namespace Mainul\PasswordPolicy\Models;

use Illuminate\Database\Eloquent\Model;

/** A runtime override of a config default (see SettingsRepository). */
class PolicySetting extends Model
{
    protected $table = 'password_policy_settings';

    protected $primaryKey = 'key';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['value' => 'json'];
    }
}
