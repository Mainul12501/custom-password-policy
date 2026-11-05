<?php

namespace Mainul\PasswordPolicy\Mfa;

/** Time-based one-time passwords (RFC 6238 / RFC 4226). */
class Totp
{
    public function __construct(
        protected int $digits = 6,
        protected int $period = 30,
        protected string $algorithm = 'sha1',
    ) {
    }

    public static function fromConfig(): static
    {
        return new static(
            (int) config('password-policy.totp.digits', 6),
            (int) config('password-policy.totp.period', 30),
            (string) config('password-policy.totp.algorithm', 'sha1'),
        );
    }

    /** A new random Base32 secret (20 bytes = 160 bits). */
    public function generateSecret(int $bytes = 20): string
    {
        return Base32::encode(random_bytes($bytes));
    }

    public function step(?int $time = null): int
    {
        return intdiv($time ?? now()->getTimestamp(), $this->period);
    }

    /** The code for a given time-step counter. */
    public function codeForStep(string $secret, int $step): string
    {
        $hash = hash_hmac($this->algorithm, pack('J', $step), Base32::decode($secret), true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);

        return str_pad((string) ($binary % (10 ** $this->digits)), $this->digits, '0', STR_PAD_LEFT);
    }

    public function code(string $secret, ?int $time = null): string
    {
        return $this->codeForStep($secret, $this->step($time));
    }

    /**
     * Check a code, allowing $window steps of clock drift either way.
     * Returns the matching time-step (so the caller can block replays) or null.
     */
    public function verify(string $secret, string $code, int $window = 1, ?int $time = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code);

        if (! preg_match('/^\d{' . $this->digits . '}$/', $code)) {
            return null;
        }

        $current = $this->step($time);
        $matched = null;

        // Walk every step so the time taken does not reveal which one matched.
        for ($offset = -$window; $offset <= $window; $offset++) {
            $step = $current + $offset;

            if ($step >= 0 && hash_equals($this->codeForStep($secret, $step), $code)) {
                $matched = $step;
            }
        }

        return $matched;
    }

    /** The otpauth:// URI that authenticator apps read from a QR code. */
    public function uri(string $secret, string $account, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);

        return 'otpauth://totp/' . $label . '?' . http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => strtoupper($this->algorithm),
            'digits'    => $this->digits,
            'period'    => $this->period,
        ], '', '&', PHP_QUERY_RFC3986);
    }
}
