<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Throwable;

/**
 * Generates and issues temporary first passwords (Policy 3.1.2 - 3.1.6).
 *
 * The plain password exists only in memory, is handed to the delivery channel
 * and is never returned, logged or stored in readable form.
 */
class TemporaryPasswordService
{
    // Visually ambiguous characters (0 O 1 l I) are left out on purpose.
    protected const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    protected const LOWER = 'abcdefghijkmnopqrstuvwxyz';
    protected const DIGIT = '23456789';
    protected const SPECIAL = '!@#$%^&*-_=+?';

    protected const MAX_ATTEMPTS = 20;

    public function __construct(
        protected DeliveryResolver $resolver,
        protected AuditLogger $audit,
    ) {
    }

    /**
     * Generate a random, non-guessable password that satisfies the complexity
     * rules (3.1.2).
     */
    public function generate(?int $length = null, ?Model $forUser = null): string
    {
        $length = max($length ?? (int) config('password-policy.temporary_password.length', 14), 12);
        $rules = config('password-policy.rules', []);
        $rule = new PasswordPolicyRule();

        // Honour a stricter configured minimum length.
        $length = max($length, (int) ($rules['min_length'] ?? 8));

        for ($i = 0; $i < self::MAX_ATTEMPTS; $i++) {
            $candidate = $this->candidate($length);

            if (! $rule->passes('password', $candidate)) {
                continue;
            }

            if ($this->isPredictable($candidate, $forUser)) {
                continue;
            }

            return $candidate;
        }

        throw new \RuntimeException('Unable to generate a compliant temporary password.');
    }

    /**
     * Set a fresh temporary password for the user, force a change at first
     * login and deliver it. Returns the name of the channel used.
     *
     * If no approved channel exists nothing is changed. If delivery fails the
     * password change is rolled back.
     */
    public function issueFor(Model&Authenticatable $user): string
    {
        $channel = $this->resolver->resolve($user);

        try {
            DB::transaction(function () use ($user, $channel) {
                $password = $this->generate(null, $user);

                $user->setTemporaryPassword(Hash::make($password));
                $user->save();

                $channel->send($user, $password);
            });
        } catch (Throwable $e) {
            $this->audit->log('temp_password_issued', AuditLogger::OUTCOME_FAILURE, $user, null, [
                'channel' => $channel->name(),
            ]);

            throw $e;
        }

        $this->audit->log('temp_password_issued', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'channel' => $channel->name(),
        ]);

        return $channel->name();
    }

    protected function candidate(int $length): string
    {
        $rules = config('password-policy.rules', []);
        $all = '';
        $chars = [];

        $pools = [
            [self::UPPER, $rules['require_uppercase'] ?? true],
            [self::LOWER, $rules['require_lowercase'] ?? true],
            [self::DIGIT, $rules['require_numeric'] ?? true],
            [self::SPECIAL, $rules['require_special'] ?? true],
        ];

        foreach ($pools as [$pool, $required]) {
            $all .= $pool;
            if ($required) {
                $chars[] = $pool[random_int(0, strlen($pool) - 1)];
            }
        }

        while (count($chars) < $length) {
            $chars[] = $all[random_int(0, strlen($all) - 1)];
        }

        // Fisher-Yates shuffle with a CSPRNG.
        for ($i = count($chars) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$chars[$i], $chars[$j]] = [$chars[$j], $chars[$i]];
        }

        return implode('', $chars);
    }

    protected function isPredictable(string $password, ?Model $user): bool
    {
        $lower = strtolower($password);

        // Three or more identical characters in a row.
        if (preg_match('/(.)\1{2,}/', $password)) {
            return true;
        }

        // Ascending or descending runs of three (abc, 123, cba, 321).
        for ($i = 0; $i < strlen($lower) - 2; $i++) {
            $a = ord($lower[$i]);
            $b = ord($lower[$i + 1]);
            $c = ord($lower[$i + 2]);
            if (($b - $a === 1 && $c - $b === 1) || ($a - $b === 1 && $b - $c === 1)) {
                return true;
            }
        }

        if ($user !== null) {
            $email = (string) ($user->{config('password-policy.columns.email', 'email')} ?? '');
            $name = (string) ($user->{config('password-policy.columns.name', 'name')} ?? '');

            $needles = array_filter([
                strtolower(strstr($email, '@', true) ?: $email),
                strtolower($name),
            ], fn ($n) => strlen($n) >= 3);

            foreach ($needles as $needle) {
                if (str_contains($lower, $needle)) {
                    return true;
                }
            }
        }

        return false;
    }
}
