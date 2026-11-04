<?php

namespace Mainul\PasswordPolicy\Models;

use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * A non-human account. It must have a named owner and a documented purpose
 * (Policy 3.9.3) and rotates on a schedule (3.9.4).
 */
class ServiceAccount extends Model
{
    protected $table = 'service_accounts';

    protected $guarded = [];

    protected static function booted(): void
    {
        static::saving(function (self $account) {
            if (trim((string) $account->owner) === '') {
                throw new InvalidArgumentException('A service account needs a named owner.');
            }

            if (trim((string) $account->purpose) === '') {
                throw new InvalidArgumentException('A service account needs a documented purpose.');
            }

            if ((int) $account->rotation_days < 1) {
                throw new InvalidArgumentException('rotation_days must be at least 1.');
            }
        });
    }

    protected function casts(): array
    {
        return [
            'known_by'         => 'array',
            'last_rotated_at'  => 'datetime',
            'next_rotation_at' => 'datetime',
        ];
    }

    public function scopeDue($query)
    {
        return $query->whereNotNull('next_rotation_at')->where('next_rotation_at', '<=', now());
    }
}
