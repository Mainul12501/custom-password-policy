<?php

namespace Mainul\PasswordPolicy\Rules;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;

/**
 * Requires the user's current password for a voluntary change (Policy 3.5.4).
 *
 * Skipped for system-forced changes (temporary password or expired password).
 * For administrator-initiated resets, simply do not apply this rule.
 */
class CurrentPasswordRule implements Rule, ValidationRule
{
    public function __construct(
        protected Authenticatable $user
    ) {}

    public function passes($attribute, $value): bool
    {
        if ($this->isSystemForced()) {
            return true;
        }

        return is_string($value)
            && $value !== ''
            && Hash::check($value, $this->user->getAuthPassword());
    }

    public function message(): string
    {
        return 'The current password is incorrect.';
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! $this->passes($attribute, $value)) {
            $fail($this->message());
        }
    }

    protected function isSystemForced(): bool
    {
        if (config('password-policy.current_password.skip_when_forced', true)
            && (bool) ($this->user->must_change_password ?? false)) {
            return true;
        }

        return (bool) config('password-policy.current_password.skip_when_expired', true)
            && app(PasswordExpiryService::class)->isExpired($this->user);
    }
}
