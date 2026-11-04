<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Exceptions\AccountLockedException;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\LoginGuard;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class LoginGuardTest extends TestCase
{
    protected function user(array $attrs = []): User
    {
        return User::create(array_merge([
            'name'                => 'T',
            'email'               => 't@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ], $attrs));
    }

    protected function guard(): LoginGuard
    {
        return app(LoginGuard::class);
    }

    public function test_healthy_and_unknown_identifiers_pass(): void
    {
        $this->user();

        $this->guard()->ensureCanAttempt('t@example.com');
        $this->guard()->ensureCanAttempt('ghost@example.com');

        $this->assertTrue(true);
    }

    public function test_disabled_account_is_rejected(): void
    {
        $this->user(['disabled_at' => now()]);

        try {
            $this->guard()->ensureCanAttempt('t@example.com');
            $this->fail('Expected AccountLockedException');
        } catch (AccountLockedException $e) {
            $this->assertSame('disabled', $e->reason);
            $this->assertNull($e->retryAfterSeconds);
        }
    }

    public function test_temporarily_locked_account_reports_retry_after(): void
    {
        $this->user(['locked_until' => now()->addMinutes(5)]);

        try {
            $this->guard()->ensureCanAttempt('t@example.com');
            $this->fail('Expected AccountLockedException');
        } catch (AccountLockedException $e) {
            $this->assertSame('temporary', $e->reason);
            $this->assertEqualsWithDelta(300, $e->retryAfterSeconds, 3);
        }
    }

    public function test_message_is_identical_for_every_reason(): void
    {
        $messages = [];

        foreach (['disabled_at' => now(), 'is_permanently_locked' => true, 'locked_until' => now()->addMinute()] as $col => $val) {
            $user = $this->user([$col => $val, 'email' => "{$col}@example.com"]);

            try {
                $this->guard()->ensureCanAttempt($user->email);
            } catch (AccountLockedException $e) {
                $messages[] = $e->getMessage();
            }
        }

        $this->assertCount(3, $messages);
        $this->assertCount(1, array_unique($messages), 'no hint about why');
    }

    public function test_account_past_grace_is_disabled_and_rejected(): void
    {
        $user = $this->user(['password_changed_at' => now()->subDays(95)]);

        $this->expectException(AccountLockedException::class);

        try {
            $this->guard()->ensureCanAttempt('t@example.com');
        } finally {
            $this->assertNotNull($user->fresh()->disabled_at);
        }
    }

    public function test_account_locked_by_the_service_is_rejected(): void
    {
        $user = $this->user();
        for ($i = 0; $i < 5; $i++) {
            app(LockoutService::class)->recordFailure($user->fresh());
        }

        $this->expectException(AccountLockedException::class);
        $this->guard()->ensureCanAttempt('t@example.com');
    }
}
