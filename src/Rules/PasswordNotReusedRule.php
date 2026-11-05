<?php

namespace Mainul\PasswordPolicy\Rules;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;
use Illuminate\Contracts\Validation\ValidationRule;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;

class PasswordNotReusedRule implements Rule, ValidationRule
{
    public function __construct(
        protected Authenticatable $user
    ) {}

    /**
     * Determine if the validation rule passes (Laravel 10 compatible).
     */
    public function passes($attribute, $value): bool
    {
        if (! config('password-policy.history.enabled', true)) {
            return true;
        }

        return ! app(PasswordHistoryService::class)->hasBeenUsed($this->user, $value);
    }

    /**
     * Get the validation error message (Laravel 10 compatible).
     */
    public function message(): string
    {
        $count = config('password-policy.history.max_reuse_count', 5);

        return "You cannot reuse any of your last {$count} passwords.";
    }

    /**
     * Run the validation rule (Laravel 11+ ValidationRule interface).
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! $this->passes($attribute, $value)) {
            $fail($this->message());
        }
    }
}
