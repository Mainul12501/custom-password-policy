<?php

namespace Mainul\PasswordPolicy\Mfa;

/**
 * Single-use backup codes. They are random and long, so a keyed SHA-256 is
 * enough to store them: the plain codes are shown once and never kept.
 */
class RecoveryCodes
{
    // No 0/O/1/l/i: easy to misread when written down.
    protected const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    /** @return array{plain: string[], stored: array<int, array{hash: string, used_at: ?string}>} */
    public static function generate(int $count = 8): array
    {
        $plain = [];
        $stored = [];

        for ($i = 0; $i < $count; $i++) {
            $raw = '';
            for ($c = 0; $c < 10; $c++) {
                $raw .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
            }

            $code = substr($raw, 0, 5) . '-' . substr($raw, 5);
            $plain[] = $code;
            $stored[] = ['hash' => self::hash($code), 'used_at' => null];
        }

        return ['plain' => $plain, 'stored' => $stored];
    }

    /**
     * Use a code. Returns the updated stored list, or null if the code is
     * wrong or already used.
     */
    public static function consume(array $stored, string $input): ?array
    {
        $hash = self::hash($input);
        $found = null;

        foreach ($stored as $i => $entry) {
            if (hash_equals((string) $entry['hash'], $hash) && empty($entry['used_at'])) {
                $found = $i;
            }
        }

        if ($found === null) {
            return null;
        }

        $stored[$found]['used_at'] = now()->toIso8601String();

        return $stored;
    }

    public static function remaining(?array $stored): int
    {
        return count(array_filter($stored ?? [], fn ($e) => empty($e['used_at'])));
    }

    protected static function hash(string $code): string
    {
        $normalized = preg_replace('/[^a-z0-9]/', '', strtolower($code));

        return hash_hmac('sha256', $normalized, (string) config('app.key'));
    }
}
