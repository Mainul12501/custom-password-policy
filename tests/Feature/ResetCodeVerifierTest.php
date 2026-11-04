<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Contracts\ResetIdentityVerifier;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Services\ResetCodeVerifier;
use Mainul\PasswordPolicy\Tests\Support\FailingChannel;
use Mainul\PasswordPolicy\Tests\Support\FakeSmsChannel;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class ResetCodeVerifierTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Route every channel through the recording fake.
        config()->set('password-policy.temporary_password.channels.mail', FakeSmsChannel::class);
        FakeSmsChannel::$texts = [];
    }

    protected function user(array $attrs = []): User
    {
        return User::create(array_merge([
            'name'     => 'T',
            'email'    => 't@example.com',
            'phone'    => '01700000000',
            'password' => Hash::make('Secret@123'),
        ], $attrs));
    }

    protected function verifier(): ResetIdentityVerifier
    {
        return app(ResetIdentityVerifier::class);
    }

    protected function lastCode(): string
    {
        preg_match('/code is (\d+)/', end(FakeSmsChannel::$texts)[1], $m);

        return $m[1];
    }

    public function test_contract_resolves_to_the_configured_verifier(): void
    {
        $this->assertInstanceOf(ResetCodeVerifier::class, $this->verifier());
    }

    public function test_issued_code_verifies_once(): void
    {
        $user = $this->user();

        $this->assertSame('sms', $this->verifier()->issue($user));
        $code = $this->lastCode();

        $this->assertSame(6, strlen($code));
        $this->assertTrue($this->verifier()->verify($user, $code));
        $this->assertFalse($this->verifier()->verify($user, $code), 'single use');
    }

    public function test_wrong_code_fails(): void
    {
        $user = $this->user();
        $this->verifier()->issue($user);
        $wrong = $this->lastCode() === '000000' ? '111111' : '000000';

        $this->assertFalse($this->verifier()->verify($user, $wrong));
    }

    public function test_code_expires(): void
    {
        $user = $this->user();
        $this->verifier()->issue($user);
        $code = $this->lastCode();

        $this->travel(11)->minutes();

        $this->assertFalse($this->verifier()->verify($user, $code));
    }

    public function test_too_many_wrong_guesses_lock_the_code(): void
    {
        $user = $this->user();
        $this->verifier()->issue($user);
        $code = $this->lastCode();
        $wrong = $code === '000000' ? '111111' : '000000';

        for ($i = 0; $i < 5; $i++) {
            $this->verifier()->verify($user, $wrong);
        }

        $this->assertFalse($this->verifier()->verify($user, $code), 'correct code no longer accepted');
    }

    public function test_new_code_replaces_the_old_one(): void
    {
        $user = $this->user();

        $this->verifier()->issue($user);
        $first = $this->lastCode();
        $this->verifier()->issue($user);
        $second = $this->lastCode();

        $this->assertSame(1, DB::table('password_reset_codes')->count());
        if ($first !== $second) {
            $this->assertFalse($this->verifier()->verify($user, $first));
        }
        $this->assertTrue($this->verifier()->verify($user, $second));
    }

    public function test_code_is_not_valid_for_another_user(): void
    {
        $user = $this->user();
        $other = $this->user(['email' => 'o@example.com']);
        $this->verifier()->issue($user);

        $this->assertFalse($this->verifier()->verify($other, $this->lastCode()));
    }

    public function test_code_is_stored_hashed_and_never_audited(): void
    {
        $user = $this->user();
        $this->verifier()->issue($user);
        $code = $this->lastCode();
        $this->verifier()->verify($user, $code);

        $stored = DB::table('password_reset_codes')->first();
        $this->assertNotSame($code, $stored->code_hash);
        $this->assertTrue(Hash::check($code, $stored->code_hash));

        $audit = json_encode(PasswordAuditLog::all()->toArray());
        $this->assertStringNotContainsString("\"{$code}\"", $audit);
        $this->assertSame(['channel' => 'sms'], PasswordAuditLog::where('event', 'reset_code_issued')->first()->context);
    }

    public function test_code_length_is_configurable(): void
    {
        config()->set('password-policy.reset.code_length', 8);
        $user = $this->user();

        $this->verifier()->issue($user);

        $this->assertSame(8, strlen($this->lastCode()));
    }

    public function test_failed_delivery_removes_the_code_and_rethrows(): void
    {
        config()->set('password-policy.temporary_password.channels.mail', FailingChannel::class);

        try {
            $this->verifier()->issue($this->user());
            $this->fail('Expected DeliveryFailedException');
        } catch (DeliveryFailedException) {
            $this->assertSame(0, DB::table('password_reset_codes')->count());
        }
    }

    public function test_user_without_a_channel_cannot_receive_a_code(): void
    {
        $this->expectException(NoSecureChannelException::class);

        $this->verifier()->issue($this->user(['email' => 'bad', 'phone' => null]));
    }

    public function test_verification_attempts_are_audited(): void
    {
        $user = $this->user();
        $this->verifier()->issue($user);

        $this->verifier()->verify($user, '999999' === $this->lastCode() ? '111111' : '999999');
        $this->verifier()->verify($user, $this->lastCode());

        $this->assertSame(
            ['failure', 'success'],
            PasswordAuditLog::where('event', 'reset_code_verified')->orderBy('id')->pluck('outcome')->all()
        );
    }
}
