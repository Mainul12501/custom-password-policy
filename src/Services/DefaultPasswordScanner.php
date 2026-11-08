<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Support\Facades\Hash;

/**
 * Finds accounts still using a known default password (Policy 3.9.5).
 *
 * Each user is hashed against every default, so this is slow on large user
 * tables. The matching password is deliberately never returned or logged.
 */
class DefaultPasswordScanner
{
    public function __construct(protected AuditLogger $audit)
    {
    }

    /**
     * @param  bool  $flag  force a password change for every account found
     * @return array<int,array{id:int|string,email:?string}>
     */
    public function scan(bool $flag = false, string|int|null $userId = null): array
    {
        $defaults = array_values(array_filter((array) config('password-policy.defaults.passwords', []), 'strlen'));
        $class = config('password-policy.user_model');
        $emailColumn = config('password-policy.columns.email', 'email');
        $found = [];

        $query = $class::query();
        if ($userId !== null && $userId !== '') {
            $query->whereKey($userId);
        }

        $query->chunkById(200, function ($users) use ($defaults, $flag, $emailColumn, &$found) {
            foreach ($users as $user) {
                foreach ($defaults as $candidate) {
                    if (! Hash::check($candidate, $user->password)) {
                        continue;
                    }

                    $found[] = ['id' => $user->getKey(), 'email' => $user->{$emailColumn}];

                    if ($flag) {
                        $user->forceFill(['must_change_password' => true])->saveQuietly();
                    }

                    $this->audit->log('default_password_found', AuditLogger::OUTCOME_ALERT, $user);

                    break;
                }
            }
        });

        return $found;
    }
}
