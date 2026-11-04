<?php

namespace Mainul\PasswordPolicy\Rules;

use Closure;
use Illuminate\Contracts\Validation\Rule;
use Illuminate\Contracts\Validation\ValidationRule;
use Mainul\PasswordPolicy\Http\Middleware\BlockSelfReset;
use Mainul\PasswordPolicy\Services\ResetEligibility;

/** Validation rule for the email field of a forgot-password form (3.6.6). */
class CanSelfResetPassword implements Rule, ValidationRule
{
    public function passes($attribute, $value): bool
    {
        $eligibility = app(ResetEligibility::class);
        $user = is_string($value) ? $eligibility->findUser($value) : null;

        return $user === null || $eligibility->canSelfReset($user);
    }

    public function message(): string
    {
        return BlockSelfReset::MESSAGE;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! $this->passes($attribute, $value)) {
            $fail($this->message());
        }
    }
}
