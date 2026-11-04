<?php

namespace Mainul\PasswordPolicy\Support;

/**
 * Strips secrets (passwords, tokens, reset codes...) from arrays before they
 * are stored or logged (Policy 3.7.2).
 */
class Redactor
{
    public const MASK = '[REDACTED]';

    /**
     * @param  array<string,mixed>  $data
     * @param  array<int,string>|null  $keys  defaults to audit.redact_keys
     * @return array<string,mixed>
     */
    public static function redact(array $data, ?array $keys = null): array
    {
        $keys = array_map('strtolower', $keys ?? config('password-policy.audit.redact_keys', []));

        $result = [];
        foreach ($data as $key => $value) {
            if (is_string($key) && in_array(strtolower($key), $keys, true)) {
                $result[$key] = self::MASK;
            } elseif (is_array($value)) {
                $result[$key] = self::redact($value, $keys);
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }
}
