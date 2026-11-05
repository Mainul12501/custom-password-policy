<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Mfa;

use Mainul\PasswordPolicy\Mfa\Base32;
use Mainul\PasswordPolicy\Mfa\RecoveryCodes;
use Mainul\PasswordPolicy\Mfa\Totp;
use Mainul\PasswordPolicy\Tests\TestCase;

class TotpTest extends TestCase
{
    /** RFC 6238 appendix B, SHA-1, 8 digits, secret "12345678901234567890". */
    public function test_rfc6238_sha1_test_vectors(): void
    {
        $secret = Base32::encode('12345678901234567890');
        $totp = new Totp(8, 30, 'sha1');

        foreach ([
            59          => '94287082',
            1111111109  => '07081804',
            1111111111  => '14050471',
            1234567890  => '89005924',
            2000000000  => '69279037',
            20000000000 => '65353130',
        ] as $time => $expected) {
            $this->assertSame($expected, $totp->code($secret, $time), "time {$time}");
        }
    }

    public function test_base32_round_trip_and_known_value(): void
    {
        $this->assertSame('MZXW6YTBOI', Base32::encode('foobar'));
        $this->assertSame('foobar', Base32::decode('mzxw 6ytb oi'));

        $bytes = random_bytes(20);
        $this->assertSame($bytes, Base32::decode(Base32::encode($bytes)));
    }

    public function test_verify_accepts_drift_within_window_only(): void
    {
        $totp = new Totp();
        $secret = $totp->generateSecret();
        $now = 1_700_000_000;
        $step = $totp->step($now);

        $this->assertSame($step, $totp->verify($secret, $totp->code($secret, $now), 1, $now));
        $this->assertSame($step - 1, $totp->verify($secret, $totp->code($secret, $now - 30), 1, $now));
        $this->assertSame($step + 1, $totp->verify($secret, $totp->code($secret, $now + 30), 1, $now));
        $this->assertNull($totp->verify($secret, $totp->code($secret, $now - 90), 1, $now));
    }

    public function test_verify_rejects_malformed_codes(): void
    {
        $totp = new Totp();
        $secret = $totp->generateSecret();

        $this->assertNull($totp->verify($secret, 'abcdef'));
        $this->assertNull($totp->verify($secret, '12345'));
        $this->assertNull($totp->verify($secret, ''));
    }

    public function test_verify_ignores_spaces_in_the_code(): void
    {
        $totp = new Totp();
        $secret = $totp->generateSecret();
        $code = $totp->code($secret, 1_700_000_000);

        $spaced = substr($code, 0, 3) . ' ' . substr($code, 3);
        $this->assertNotNull($totp->verify($secret, $spaced, 1, 1_700_000_000));
    }

    public function test_uri_contains_secret_and_issuer(): void
    {
        $uri = (new Totp())->uri('JBSWY3DPEHPK3PXP', 'a@b.com', 'Remark HB');

        $this->assertStringStartsWith('otpauth://totp/Remark%20HB:a%40b.com?', $uri);
        $this->assertStringContainsString('secret=JBSWY3DPEHPK3PXP', $uri);
        $this->assertStringContainsString('issuer=Remark%20HB', $uri);
    }

    public function test_recovery_codes_are_single_use_and_stored_hashed(): void
    {
        $generated = RecoveryCodes::generate(3);
        $code = $generated['plain'][0];

        $this->assertCount(3, $generated['plain']);
        $this->assertMatchesRegularExpression('/^[a-z2-9]{5}-[a-z2-9]{5}$/', $code);
        $this->assertStringNotContainsString($code, json_encode($generated['stored']));

        $after = RecoveryCodes::consume($generated['stored'], strtoupper($code));
        $this->assertNotNull($after);
        $this->assertSame(2, RecoveryCodes::remaining($after));

        $this->assertNull(RecoveryCodes::consume($after, $code), 'second use');
        $this->assertNull(RecoveryCodes::consume($after, 'zzzzz-zzzzz'));
    }
}
