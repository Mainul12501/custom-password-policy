<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Events\AccountLocked;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class LockoutServiceTest extends TestCase
{
    protected function user(): User
    {
        return User::create([
            'name'                => 'T',
            'email'               => 't@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);
    }

    protected function service(): LockoutService
    {
        return app(LockoutService::class);
    }

    /** Failures without an IP, so only the attempt counter is exercised. */
    protected function failTimes(User $user, int $times): void
    {
        for ($i = 0; $i < $times; $i++) {
            $this->service()->recordFailure($user);
        }
    }

    public function test_four_failures_do_not_lock(): void
    {
        $user = $this->user();

        $this->failTimes($user, 4);

        $this->assertFalse($this->service()->isLocked($user));
        $this->assertSame(4, (int) $user->failed_login_count);
    }

    public function test_fifth_failure_locks_for_five_minutes(): void
    {
        $user = $this->user();

        $this->failTimes($user, 5);

        $state = $this->service()->lockState($user);
        $this->assertSame(LockoutService::LOCK_TEMPORARY, $state['type']);
        $this->assertEqualsWithDelta(300, now()->diffInSeconds($state['until']), 2);
        $this->assertSame(0, (int) $user->failed_login_count);
        $this->assertSame(1, (int) $user->lockout_level);
    }

    public function test_lock_expires_by_itself(): void
    {
        $user = $this->user();
        $this->failTimes($user, 5);

        $this->travel(301)->seconds();

        $this->assertFalse($this->service()->isLocked($user->fresh()));
    }

    public function test_escalates_to_10_then_30_minutes(): void
    {
        $user = $this->user();

        $this->failTimes($user, 5);
        $this->travel(6)->minutes();

        $this->failTimes($user->fresh(), 5);
        $second = $this->service()->lockState($user->fresh());
        $this->assertEqualsWithDelta(600, now()->diffInSeconds($second['until']), 2);

        $this->travel(11)->minutes();

        $this->failTimes($user->fresh(), 5);
        $third = $this->service()->lockState($user->fresh());
        $this->assertEqualsWithDelta(1800, now()->diffInSeconds($third['until']), 2);
        $this->assertSame(3, (int) $user->fresh()->lockout_level);
    }

    public function test_fourth_cycle_is_extended_and_needs_identity_verification(): void
    {
        $user = $this->user();

        foreach ([6, 11, 31] as $minutes) {
            $this->failTimes($user->fresh(), 5);
            $this->travel($minutes)->minutes();
        }

        $this->failTimes($user->fresh(), 5);
        $fresh = $user->fresh();
        $state = $this->service()->lockState($fresh);

        $this->assertSame(4, (int) $fresh->lockout_level);
        $this->assertTrue((bool) $fresh->requires_identity_verification);
        $this->assertEqualsWithDelta(7200, now()->diffInSeconds($state['until']), 2);

        // Still locked after the time has passed: an unlock is required.
        $this->travel(3)->hours();
        $this->assertSame(LockoutService::LOCK_VERIFICATION, $this->service()->lockState($fresh->fresh())['type']);
    }

    public function test_failures_while_locked_do_not_escalate(): void
    {
        $user = $this->user();
        $this->failTimes($user, 5);

        $this->failTimes($user->fresh(), 20);

        $this->assertSame(1, (int) $user->fresh()->lockout_level);
    }

    public function test_success_resets_the_failure_counter(): void
    {
        $user = $this->user();
        $this->failTimes($user, 4);

        $this->service()->recordSuccess($user->fresh());
        $this->failTimes($user->fresh(), 4);

        $this->assertFalse($this->service()->isLocked($user->fresh()));
    }

    public function test_cycle_counter_resets_after_quiet_period(): void
    {
        $user = $this->user();
        $this->failTimes($user, 5);
        $this->travel(25)->hours();

        $this->failTimes($user->fresh(), 5);

        $this->assertSame(1, (int) $user->fresh()->lockout_level, 'back to the 5 minute cycle');
    }

    public function test_ip_burst_locks_permanently(): void
    {
        $user = $this->user();

        for ($i = 0; $i < 5; $i++) {
            $this->service()->recordFailure($user->fresh(), '203.0.113.9');
        }

        $fresh = $user->fresh();
        $this->assertTrue((bool) $fresh->is_permanently_locked);
        $this->assertSame(LockoutService::LOCK_PERMANENT, $this->service()->lockState($fresh)['type']);

        $this->travel(2)->days();
        $this->assertTrue($this->service()->isLocked($fresh->fresh()), 'time never unlocks it');
    }

    public function test_failures_from_different_ips_are_not_a_burst(): void
    {
        $user = $this->user();

        for ($i = 1; $i <= 4; $i++) {
            $this->service()->recordFailure($user->fresh(), "203.0.113.{$i}");
        }

        $this->assertFalse((bool) $user->fresh()->is_permanently_locked);
    }

    public function test_burst_outside_the_window_is_not_counted(): void
    {
        $user = $this->user();

        for ($i = 0; $i < 4; $i++) {
            $this->service()->recordFailure($user->fresh(), '203.0.113.9');
        }
        $this->travel(61)->seconds();
        $this->service()->recordFailure($user->fresh(), '203.0.113.9');

        $this->assertFalse((bool) $user->fresh()->is_permanently_locked);
    }

    public function test_ip_burst_can_be_disabled(): void
    {
        config()->set('password-policy.lockout.ip_burst.enabled', false);
        $user = $this->user();

        for ($i = 0; $i < 5; $i++) {
            $this->service()->recordFailure($user->fresh(), '203.0.113.9');
        }

        $this->assertFalse((bool) $user->fresh()->is_permanently_locked);
        $this->assertSame(LockoutService::LOCK_TEMPORARY, $this->service()->lockState($user->fresh())['type']);
    }

    public function test_permanent_lock_needs_a_verifier_to_unlock(): void
    {
        $user = $this->user();
        for ($i = 0; $i < 5; $i++) {
            $this->service()->recordFailure($user->fresh(), '203.0.113.9');
        }

        try {
            $this->service()->unlock($user->fresh());
            $this->fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException) {
            $this->assertTrue($this->service()->isLocked($user->fresh()));
        }

        $this->service()->unlock($user->fresh(), 'admin#7');

        $fresh = $user->fresh();
        $this->assertFalse($this->service()->isLocked($fresh));
        $this->assertSame(0, (int) $fresh->lockout_level);

        $log = PasswordAuditLog::where('event', 'account_unlocked')->firstOrFail();
        $this->assertSame('admin#7', $log->context['verified_by']);
        $this->assertSame('permanent', $log->context['previous_lock']);
    }

    public function test_temporary_lock_can_be_lifted_without_verifier(): void
    {
        $user = $this->user();
        $this->failTimes($user, 5);

        $this->service()->unlock($user->fresh());

        $this->assertFalse($this->service()->isLocked($user->fresh()));
    }

    public function test_locking_is_audited_and_dispatches_event(): void
    {
        Event::fake([AccountLocked::class]);
        $user = $this->user();

        $this->failTimes($user, 5);

        Event::assertDispatched(AccountLocked::class, fn ($e) => $e->level === 1 && $e->minutes === 5);
        $log = PasswordAuditLog::where('event', 'account_locked')->firstOrFail();
        $this->assertSame('blocked', $log->outcome);
        $this->assertSame('failed_attempts', $log->context['reason']);
    }

    public function test_laravel_auth_events_drive_the_counters(): void
    {
        $user = $this->user();

        for ($i = 0; $i < 5; $i++) {
            Event::dispatch(new Failed('web', $user->fresh(), ['email' => 't@example.com', 'password' => 'x']));
        }

        $this->assertTrue($this->service()->isLocked($user->fresh()));
    }

    public function test_failed_event_for_unknown_user_is_ignored(): void
    {
        Event::dispatch(new Failed('web', null, ['email' => 'ghost@example.com', 'password' => 'x']));

        $this->assertTrue(true);
    }

    public function test_login_event_clears_failure_count(): void
    {
        $user = $this->user();
        $this->failTimes($user, 3);

        Event::dispatch(new Login('web', $user->fresh(), false));

        $this->assertSame(0, (int) $user->fresh()->failed_login_count);
    }

    public function test_lockout_can_be_turned_off(): void
    {
        config()->set('password-policy.lockout.enabled', false);
        $user = $this->user();

        $this->failTimes($user, 10);

        $this->assertFalse($this->service()->isLocked($user->fresh()));
    }
}
