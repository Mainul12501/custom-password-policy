<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\ServiceAccountService;
use Mainul\PasswordPolicy\Tests\Support\FailingVault;
use Mainul\PasswordPolicy\Tests\Support\MailInspector;
use Mainul\PasswordPolicy\Tests\Support\RecordingVault;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;
use RuntimeException;

class ServiceAccountTest extends TestCase
{
    use MailInspector;

    protected function setUp(): void
    {
        parent::setUp();

        RecordingVault::$stored = [];
    }

    protected function user(string $email = 'svc@example.com', $changedAt = null): User
    {
        return User::create([
            'name'                => 'svc',
            'email'               => $email,
            'password'            => Hash::make('Initial@Secret1'),
            'password_changed_at' => $changedAt ?? now(),
        ]);
    }

    protected function service(): ServiceAccountService
    {
        return app(ServiceAccountService::class);
    }

    public function test_owner_and_purpose_are_mandatory(): void
    {
        foreach ([['', 'billing sync'], ['ops-team', ''], ['  ', 'x']] as [$owner, $purpose]) {
            try {
                $this->service()->register($this->user("u{$owner}{$purpose}@example.com"), $owner, $purpose);
                $this->fail('Expected InvalidArgumentException');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }

        $this->assertSame(0, ServiceAccount::count());
    }

    public function test_registration_schedules_the_first_rotation(): void
    {
        $account = $this->service()->register($this->user(), 'ops-team', 'Nightly billing sync', 30);

        $this->assertSame('ops-team', $account->owner);
        $this->assertEqualsWithDelta(30 * 86400, now()->diffInSeconds($account->next_rotation_at), 5);
        $this->assertSame(1, PasswordAuditLog::where('event', 'service_account_registered')->count());
    }

    public function test_default_rotation_period_comes_from_config(): void
    {
        config()->set('password-policy.service_accounts.default_rotation_days', 45);

        $account = $this->service()->register($this->user(), 'ops', 'sync');

        $this->assertSame(45, $account->rotation_days);
    }

    public function test_registering_twice_updates_instead_of_duplicating(): void
    {
        $user = $this->user();

        $this->service()->register($user, 'ops', 'sync');
        $this->service()->register($user, 'new-owner', 'sync v2');

        $this->assertSame(1, ServiceAccount::count());
        $this->assertSame('new-owner', ServiceAccount::first()->owner);
    }

    public function test_service_accounts_do_not_expire_or_get_auto_disabled(): void
    {
        $old = $this->user('svc@example.com', now()->subDays(400));
        $human = $this->user('human@example.com', now()->subDays(400));
        $this->service()->register($old, 'ops', 'sync');

        $expiry = app(PasswordExpiryService::class);
        $this->assertFalse($expiry->isExpired($old));
        $this->assertFalse($expiry->isDisableDue($old));
        $this->assertTrue($expiry->isExpired($human));

        $this->artisan('password-policy:disable-expired')->expectsOutput('Disabled 1 account(s).')->assertSuccessful();

        $this->assertNull($old->fresh()->disabled_at);
        $this->assertNotNull($human->fresh()->disabled_at);
    }

    public function test_rotation_hands_the_secret_to_the_vault_only(): void
    {
        config()->set('password-policy.service_accounts.vault', RecordingVault::class);
        $user = $this->user();
        $this->service()->register($user, 'ops', 'sync', 30);
        $oldHash = $user->password;

        $this->service()->rotate($user->fresh());

        $this->assertCount(1, RecordingVault::$stored);
        [$id, $secret] = RecordingVault::$stored[0];

        $fresh = $user->fresh();
        $this->assertSame($user->id, $id);
        $this->assertGreaterThanOrEqual(32, strlen($secret));
        $this->assertTrue((new PasswordPolicyRule())->passes('p', $secret));
        $this->assertTrue(Hash::check($secret, $fresh->password));
        $this->assertNotSame($oldHash, $fresh->password);
        $this->assertFalse($fresh->mustChangePassword(), 'service accounts never get a forced change');
        $this->assertGreaterThanOrEqual(1, $fresh->passwordHistories()->count());

        $account = ServiceAccount::first();
        $this->assertEqualsWithDelta(30 * 86400, now()->diffInSeconds($account->next_rotation_at), 5);
        $this->assertNotNull($account->last_rotated_at);

        $audit = json_encode(PasswordAuditLog::all()->toArray());
        $this->assertStringNotContainsString($secret, $audit);
        $this->assertSame(1, PasswordAuditLog::where('event', 'service_account_rotated')->count());
    }

    public function test_rotation_without_a_vault_is_refused_and_changes_nothing(): void
    {
        $user = $this->user();
        $this->service()->register($user, 'ops', 'sync');
        $before = $user->fresh()->password;

        try {
            $this->service()->rotate($user->fresh());
            $this->fail('Expected RuntimeException');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('vault', $e->getMessage());
            $this->assertSame($before, $user->fresh()->password);
        }
    }

    public function test_a_failing_vault_rolls_the_rotation_back(): void
    {
        config()->set('password-policy.service_accounts.vault', FailingVault::class);
        $user = $this->user();
        $this->service()->register($user, 'ops', 'sync');
        $before = $user->fresh()->password;
        $nextBefore = ServiceAccount::first()->next_rotation_at;

        try {
            $this->service()->rotate($user->fresh());
            $this->fail('Expected RuntimeException');
        } catch (RuntimeException $e) {
            $this->assertSame('vault unreachable', $e->getMessage());
        }

        $this->assertSame($before, $user->fresh()->password, 'account and vault must not disagree');
        $this->assertEquals($nextBefore, ServiceAccount::first()->next_rotation_at);
        $this->assertSame(0, PasswordAuditLog::where('event', 'service_account_rotated')->count());
    }

    public function test_rotating_an_unregistered_user_fails(): void
    {
        config()->set('password-policy.service_accounts.vault', RecordingVault::class);

        $this->expectException(RuntimeException::class);
        $this->service()->rotate($this->user());
    }

    public function test_due_lists_only_overdue_accounts(): void
    {
        $a = $this->user('a@example.com');
        $b = $this->user('b@example.com');
        $this->service()->register($a, 'ops', 'a', 30);
        $this->service()->register($b, 'ops', 'b', 30);
        ServiceAccount::where('user_id', $a->id)->update(['next_rotation_at' => now()->subDay()]);

        $due = $this->service()->due();

        $this->assertSame([$a->id], $due->pluck('user_id')->all());
    }

    public function test_rotation_due_command_lists_notifies_and_rotates(): void
    {
        $this->useArrayMailer();
        config()->set('password-policy.service_accounts.vault', RecordingVault::class);
        config()->set('password-policy.service_accounts.notify_recipients', ['security@example.com']);

        $user = $this->user();
        $this->service()->register($user, 'owner@example.com', 'Nightly sync', 30);
        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);

        $this->artisan('password-policy:rotation-due --notify --rotate')
            ->expectsOutputToContain('Nightly sync')
            ->expectsOutputToContain('Notified 2 recipient(s).')
            ->expectsOutputToContain("Rotated account [{$user->id}].")
            ->assertSuccessful();

        $this->assertCount(1, RecordingVault::$stored);
        $this->assertSame([], $this->service()->due()->all());
        $this->assertStringContainsString('Nightly sync', $this->sentTextBodies()[0]);
    }

    public function test_rotation_due_command_reports_failures_per_account(): void
    {
        config()->set('password-policy.service_accounts.vault', FailingVault::class);
        $this->service()->register($this->user(), 'ops', 'sync', 30);
        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);

        $this->artisan('password-policy:rotation-due --rotate')
            ->expectsOutputToContain('not rotated: vault unreachable')
            ->assertFailed();
    }

    public function test_rotation_due_command_when_nothing_is_due(): void
    {
        $this->artisan('password-policy:rotation-due')
            ->expectsOutput('No service account rotations are due.')
            ->assertSuccessful();
    }
}
