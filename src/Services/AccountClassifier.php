<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use Throwable;

/** Tells admin, service and ordinary accounts apart. */
class AccountClassifier
{
    /** @var array<string,bool> */
    protected array $serviceCache = [];

    public function __construct(protected ResetEligibility $roles)
    {
    }

    public function isAdmin(Authenticatable $user): bool
    {
        $flag = config('password-policy.admin.flag_attribute');

        if ($flag && (bool) ($user->{$flag} ?? false)) {
            return true;
        }

        $adminRoles = array_map('strtoupper', (array) config('password-policy.admin.roles', []));

        return array_intersect($this->roles->rolesOf($user), $adminRoles) !== [];
    }

    public function isServiceAccount(Authenticatable $user): bool
    {
        $id = (string) $user->getAuthIdentifier();

        if (! array_key_exists($id, $this->serviceCache)) {
            try {
                $this->serviceCache[$id] = ServiceAccount::where('user_id', $id)->exists();
            } catch (Throwable) {
                // Migration not run yet: treat everyone as an ordinary account.
                $this->serviceCache[$id] = false;
            }
        }

        return $this->serviceCache[$id];
    }

    public function forget(Authenticatable $user): void
    {
        unset($this->serviceCache[(string) $user->getAuthIdentifier()]);
    }
}
