<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class DisableExpiredAccountsCommandTest extends TestCase
{
    protected function user(string $email, $changedAt): User
    {
        return User::create([
            'name'                => 'T',
            'email'               => $email,
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => $changedAt,
        ]);
    }

    public function test_disables_only_accounts_past_expiry_plus_grace(): void
    {
        $fresh = $this->user('fresh@example.com', now()->subDays(10));
        $expired = $this->user('expired@example.com', now()->subDays(90)->subHours(5));
        $overdue = $this->user('overdue@example.com', now()->subDays(92));

        $this->artisan('password-policy:disable-expired')
            ->expectsOutput('Disabled 1 account(s).')
            ->assertSuccessful();

        $this->assertNull($fresh->fresh()->disabled_at);
        $this->assertNull($expired->fresh()->disabled_at, 'inside the 1 day grace period');
        $this->assertNotNull($overdue->fresh()->disabled_at);
        $this->assertSame('password_expired', $overdue->fresh()->disabled_reason);
    }

    public function test_users_without_a_change_date_are_skipped(): void
    {
        $user = $this->user('legacy@example.com', null);
        $user->forceFill(['password_changed_at' => null])->saveQuietly();

        $this->artisan('password-policy:disable-expired')->assertSuccessful();

        $this->assertNull($user->fresh()->disabled_at);
    }

    public function test_dry_run_changes_nothing(): void
    {
        $overdue = $this->user('overdue@example.com', now()->subDays(100));

        $this->artisan('password-policy:disable-expired --dry-run')
            ->expectsOutput('Would disable 1 account(s).')
            ->assertSuccessful();

        $this->assertNull($overdue->fresh()->disabled_at);
    }

    public function test_already_disabled_accounts_are_not_touched_again(): void
    {
        $overdue = $this->user('overdue@example.com', now()->subDays(100));
        $overdue->forceFill(['disabled_at' => now()->subDay(), 'disabled_reason' => 'leaver'])->saveQuietly();

        $this->artisan('password-policy:disable-expired')->expectsOutput('Disabled 0 account(s).');

        $this->assertSame('leaver', $overdue->fresh()->disabled_reason);
    }

    public function test_grace_days_are_configurable(): void
    {
        config()->set('password-policy.expiry.grace_days', 10);
        $user = $this->user('a@example.com', now()->subDays(95));

        $this->artisan('password-policy:disable-expired')->assertSuccessful();

        $this->assertNull($user->fresh()->disabled_at);
    }

    public function test_does_nothing_when_auto_disable_is_off(): void
    {
        config()->set('password-policy.expiry.auto_disable', false);
        $user = $this->user('a@example.com', now()->subDays(500));

        $this->artisan('password-policy:disable-expired')
            ->expectsOutput('Automatic disabling is turned off.')
            ->assertSuccessful();

        $this->assertNull($user->fresh()->disabled_at);
    }

    public function test_command_is_scheduled_daily(): void
    {
        $events = collect(app(\Illuminate\Console\Scheduling\Schedule::class)->events())
            ->filter(fn ($e) => str_contains($e->command, 'password-policy:disable-expired'));

        $this->assertCount(1, $events);
        $this->assertSame('0 0 * * *', $events->first()->expression);
    }

    public function test_is_disable_due_boundaries(): void
    {
        $service = app(PasswordExpiryService::class);

        $this->assertFalse($service->isDisableDue($this->user('a@example.com', now()->subDays(90))));
        $this->assertFalse($service->isDisableDue($this->user('b@example.com', now()->subDays(91)->addHour())));
        $this->assertTrue($service->isDisableDue($this->user('c@example.com', now()->subDays(91)->subHour())));
    }
}
