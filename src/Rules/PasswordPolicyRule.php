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

        $minLength = $config['min_length'] ?? 11;

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

        $lower = mb_strtolower((string) $value);

        foreach ((array) ($config['banned_words'] ?? []) as $word) {
            $word = mb_strtolower(trim((string) $word));
            if ($word !== '' && str_contains($lower, $word)) {
                $this->failures[] = 'no common or company-related words';
                break;
            }
        }

        if (($config['forbid_patterns'] ?? false) && $this->hasTrivialPattern($lower)) {
            $this->failures[] = 'no repeated or sequential characters';
        }

        if (($config['forbid_personal_info'] ?? false) && $this->user && $this->containsPersonalInfo($lower)) {
            $this->failures[] = 'no personal information (name, email, phone, birthdate)';
        }

        return empty($this->failures);
    }

    protected function hasTrivialPattern(string $value): bool
    {
        if (preg_match('/(.)\1{3,}/u', $value)) {
            return true;
        }

        $chars = preg_split('//u', $value, -1, PREG_SPLIT_NO_EMPTY);
        $run = 1;
        $dir = 0;

        for ($i = 1, $n = count($chars); $i < $n; $i++) {
            $diff = mb_ord($chars[$i]) - mb_ord($chars[$i - 1]);

            if (($diff === 1 || $diff === -1) && ctype_alnum($chars[$i]) && ctype_alnum($chars[$i - 1])) {
                $run = ($diff === $dir) ? $run + 1 : 2;
                $dir = $diff;
                if ($run >= 4) {
                    return true;
                }
            } else {
                $run = 1;
                $dir = 0;
            }
        }

        return false;
    }

    protected function containsPersonalInfo(string $value): bool
    {
        $columns = config('password-policy.columns', []);
        $tokens = [];

        $name = (string) $this->attr($columns['name'] ?? 'name');
        foreach (preg_split('/[\s._-]+/u', mb_strtolower($name), -1, PREG_SPLIT_NO_EMPTY) as $part) {
            $tokens[] = $part;
        }

        $email = mb_strtolower((string) $this->attr($columns['email'] ?? 'email'));
        if ($email !== '') {
            $tokens[] = explode('@', $email)[0];
        }

        $phone = preg_replace('/\D+/', '', (string) $this->attr($columns['phone'] ?? 'phone'));
        if (strlen($phone) >= 6) {
            $tokens[] = $phone;
            $tokens[] = substr($phone, -8);
        }

        $birth = $this->attr($columns['birthdate'] ?? 'birthdate');
        if ($birth) {
            try {
                $date = \Illuminate\Support\Carbon::parse($birth);
                array_push($tokens, $date->format('dmY'), $date->format('Ymd'), $date->format('mdY'), $date->format('dmy'));
            } catch (\Throwable) {
                // Unparseable date: nothing to compare.
            }
        }

        foreach ($tokens as $token) {
            if (mb_strlen($token) >= 3 && str_contains($value, $token)) {
                return true;
            }
        }

        return false;
    }

    protected function attr(string $key): mixed
    {
        return $this->user ? data_get($this->user, $key) : null;
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
