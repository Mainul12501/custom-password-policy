<?php

namespace Mainul\PasswordPolicy\Models;

use Illuminate\Database\Eloquent\Model;

class PasswordAuditLog extends Model
{
    public const UPDATED_AT = null;

    protected $table = 'password_audit_logs';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'context'    => 'array',
            'created_at' => 'datetime',
        ];
    }
}
