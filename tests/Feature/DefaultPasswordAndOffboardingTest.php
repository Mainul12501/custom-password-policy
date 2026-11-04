<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use Mainul\PasswordPolicy\Services\OffboardingService;
use Mainul\PasswordPolicy\Services\ServiceAccountService;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class DefaultPasswordAndOffboardingTest extends TestCase
{
    protected function user(string $email, string $password = 'Str0ng!Unique#Pass', array $attrs = []): User
    {
        return User::create(array_merge([
            'name'                => $email,
            'email'               => $email,
            'password'            => Hash::make($password),
            'password_changed_at' => now(),
        ], $attrs));
    }

    // ---- 3.9.5 default passwords --------------------------------------

    public function test_command_succeeds_when_no_default_password_is_in_use(): void
    {
        $this->user('a@example.com');

        $this->artisan('password-policy:check-defaults')
            ->expectsOutput('No account uses a known default password.')
            ->assertSuccessful();
    }

    public function test_command_finds_default_passwords_and_fails(): void
    {
        $this->user('good@example.com');
        $bad = $this->user('bad@example.com', 'admin123');

        $this->artisan('password-policy:check-defaults')
            ->expectsOutputToContain('1 account(s) use a default password.')
            ->expectsOutputToContain('bad@example.com')
            ->assertFailed();

        $this->assertFalse($bad->fresh()->mustChangePassword(), 'read-only without --flag');
    }

    public function test_flag_option_forces_a_password_change(): void
    {
        $bad = $this->user('bad@example.com', 'Welcome@123');
        $good = $this->user('good@example.com');

        $this->artisan('password-policy:check-defaults --flag')->assertFailed();

        $this->assertTrue($bad->fresh()->mustChangePassword());
        $this->assertFalse($good->fresh()->mustChangePassword());
    }

    public function test_default_list_is_configurable(): void
    {
        config()->set('password-policy.defaults.passwords', ['Vendor#Default9']);
        $this->user('a@example.com', 'Vendor#Default9');
        $this->user('b@example.com', 'admin123');

        $this->artisan('password-policy:check-defaults')
            ->expectsOutputToContain('1 account(s)')
            ->assertFailed();
    }

    public function test_single_user_check(): void
    {
        $this->user('bad@example.com', 'password');
        $good = $this->user('good@example.com');

        $this->artisan("password-policy:check-defaults --user={$good->id}")->assertSuccessful();
    }

    public function test_found_default_is_audited_without_the_password(): void
    {
        $bad = $this->user('bad@example.com', 'Changeme@123');

        $this->artisan('password-policy:check-defaults')->assertFailed();

        $log = PasswordAuditLog::where('event', 'default_password_found')->firstOrFail();
        $this->assertSame($bad->id, $log->user_id);
        $this->assertSame('alert', $log->outcome);
        $this->assertStringNotContainsString('Changeme', json_encode($log->toArray()));
    }

    // ---- 3.8.3 / 3.8.5 leavers ----------------------------------------

    public function test_offboarding_disables_the_leaver_and_ends_sessions(): void
    {
        $leaver = $this->user('leaver@example.com');

        app(OffboardingService::class)->offboard($leaver, 'hr-bot');

        $fresh = $leaver->fresh();
        $this->assertNotNull($fresh->disabled_at);
        $this->assertSame('leaver', $fresh->disabled_reason);
        $this->assertSame(1, (int) $fresh->session_version);
    }

    public function test_only_accounts_the_leaver_knew_become_due_for_rotation(): void
    {
        $leaver = $this->user('leaver@example.com');
        $colleague = $this->user('colleague@example.com');
        $svcA = $this->user('svc-a@example.com');
        $svcB = $this->user('svc-b@example.com');
        $svcC = $this->user('svc-c@example.com');
        $registry = app(ServiceAccountService::class);

        $registry->register($svcA, 'ops', 'a', 90, [$leaver->id, $colleague->id]);
        $registry->register($svcB, 'ops', 'b', 90, [$colleague->id]);
        $registry->register($svcC, 'ops', 'c', 90, []);

        $exposed = app(OffboardingService::class)->offboard($leaver);

        $this->assertSame([$svcA->id], $exposed->pluck('user_id')->all());
        $this->assertSame([$svcA->id], $registry->due()->pluck('user_id')->all());
        $this->assertTrue(ServiceAccount::where('user_id', $svcB->id)->first()->next_rotation_at->isFuture());
    }

    public function test_offboarding_is_audited(): void
    {
        $leaver = $this->user('leaver@example.com');
        $svc = $this->user('svc@example.com');
        app(ServiceAccountService::class)->register($svc, 'ops', 'a', 90, [$leaver->id]);

        app(OffboardingService::class)->offboard($leaver, 'hr-bot');

        $log = PasswordAuditLog::where('event', 'offboarded')->firstOrFail();
        $this->assertSame([$svc->id], $log->context['rotation_required']);
        $this->assertSame('hr-bot', $log->context['actor']);
    }

    public function test_offboarding_twice_is_harmless(): void
    {
        $leaver = $this->user('leaver@example.com');

        app(OffboardingService::class)->offboard($leaver);
        app(OffboardingService::class)->offboard($leaver->fresh());

        $this->assertSame(1, (int) $leaver->fresh()->session_version);
    }

    public function test_command_works_by_email_and_lists_exposed_accounts(): void
    {
        $leaver = $this->user('leaver@example.com');
        $svc = $this->user('svc@example.com');
        app(ServiceAccountService::class)->register($svc, 'ops-team', 'Payment gateway', 90, [$leaver->id]);

        $this->artisan('password-policy:offboard leaver@example.com --actor=hr')
            ->expectsOutputToContain('disabled and all sessions ended')
            ->expectsOutputToContain('Payment gateway')
            ->assertSuccessful();

        $this->assertNotNull($leaver->fresh()->disabled_at);
    }

    public function test_command_works_by_id_and_reports_when_nothing_to_rotate(): void
    {
        $leaver = $this->user('leaver@example.com');

        $this->artisan("password-policy:offboard {$leaver->id}")
            ->expectsOutputToContain('No service or shared accounts')
            ->assertSuccessful();
    }

    public function test_command_fails_for_an_unknown_user(): void
    {
        $this->artisan('password-policy:offboard ghost@example.com')
            ->expectsOutputToContain('No user found')
            ->assertFailed();
    }
}
