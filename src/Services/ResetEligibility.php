<?php

namespace Mainul\PasswordPolicy\Services;

use BackedEnum;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;

/**
 * Decides whether a user may reset a forgotten password on their own.
 * Low-clearance roles (default BA, SO) must contact an administrator
 * (Policy 3.6.6).
 */
class ResetEligibility
{
    public function canSelfReset(Authenticatable $user): bool
    {
        $restricted = array_map('strtoupper', (array) config('password-policy.reset.restricted_roles', []));

        return array_intersect($this->rolesOf($user), $restricted) === [];
    }

    /** @return array<int,string> upper-cased role names */
    public function rolesOf(Authenticatable $user): array
    {
        $resolver = config('password-policy.reset.role_resolver');

        $raw = $resolver
            ? app($resolver)($user)
            : ($user->{config('password-policy.reset.role_attribute', 'role')} ?? null);

        if ($raw instanceof Collection) {
            $raw = $raw->all();
        }

        $roles = [];
        foreach ((array) $raw as $role) {
            $role = $role instanceof BackedEnum ? $role->value : $role;

            if (is_scalar($role) && (string) $role !== '') {
                $roles[] = strtoupper(trim((string) $role));
            }
        }

        return $roles;
    }

    /** Look up a user by the configured email column. */
    public function findUser(?string $email): ?Authenticatable
    {
        if ($email === null || $email === '') {
            return null;
        }

        $class = config('password-policy.user_model');

        return $class::query()->where(config('password-policy.columns.email', 'email'), $email)->first();
    }
}
