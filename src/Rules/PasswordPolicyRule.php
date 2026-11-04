<?php

namespace Mainul\PasswordPolicy\Rules;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\Rule;
use Mainul\PasswordPolicy\Services\PolicyProfile;
use Illuminate\Contracts\Validation\ValidationRule;

class PasswordPolicyRule implements Rule, ValidationRule
{
    protected array $failures = [];

    public function __construct(protected ?Authenticatable $user = null)
    {
    }

    /**
     * Rule that applies the stricter admin settings when $user is an admin
     * (Policy 3.9.2). Without a user the global rules apply.
     */
    public static function for(?Authenticatable $user): static
    {
        return new static($user);
    }

    /**
     * Determine if the validation rule passes (Laravel 10 compatible).
     */
    public function passes($attribute, $value): bool
    {
        $this->failures = [];
        $config = app(PolicyProfile::class)->rules($this->user);

        $minLength = $config['min_length'] ?? 8;

        if (mb_strlen($value) < $minLength) {
            $this->failures[] = "at least {$minLength} characters";
        }

        if (($config['require_uppercase'] ?? true) && ! preg_match('/[A-Z]/', $value)) {
            $this->failures[] = 'one uppercase letter';
        }

        if (($config['require_lowercase'] ?? true) && ! preg_match('/[a-z]/', $value)) {
            $this->failures[] = 'one lowercase letter';
        }

        if (($config['require_numeric'] ?? true) && ! preg_match('/[0-9]/', $value)) {
            $this->failures[] = 'one number';
        }

        if (($config['require_special'] ?? true) && ! preg_match('/[^A-Za-z0-9]/', $value)) {
            $this->failures[] = 'one special character';
        }

        return empty($this->failures);
    }

    /**
     * Get the validation error message (Laravel 10 compatible).
     */
    public function message(): string
    {
        if (empty($this->failures)) {
            return 'The :attribute does not meet the password policy requirements.';
        }

        return 'The :attribute must contain ' . implode(', ', $this->failures) . '.';
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
