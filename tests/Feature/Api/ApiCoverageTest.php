<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Api;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Schema;
use Mainul\PasswordPolicy\Mfa\RecoveryCodes;
use Mainul\PasswordPolicy\Mfa\Totp;
use Mainul\PasswordPolicy\Models\KnownLogin;
use Mainul\PasswordPolicy\Models\MfaCredential;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use Mainul\PasswordPolicy\Tests\Support\FakeMfaDriver;
use Mainul\PasswordPolicy\Tests\Support\RecordingVault;
use Mainul\PasswordPolicy\Tests\Support\TestToken;
use Mainul\PasswordPolicy\Tests\Support\TokenUser;

/** Second half of the API tests: custom MFA drivers, tokens, locking, service accounts. */
class ApiCoverageTest extends ApiTestCase
{
    protected function enableTotp(): void
    {
        config()->set('password-policy.totp.enabled', true);
        config()->set('password-policy.totp.grace_days', 0);
    }

    /** Enrolled authenticator app. Returns the secret. */
    protected function enrol($user, int $codes = 2): string
    {
        $secret = (new Totp())->generateSecret();
        MfaCredential::create([
            'user_id' => $user->id, 'secret' => $secret, 'confirmed_at' => now(),
            'recovery_codes' => RecoveryCodes::generate($codes)['stored'],
        ]);

        return $secret;
    }

    // --- custom MFA driver ------------------------------------------------------------

    public function test_a_custom_mfa_driver_can_challenge_and_verify_through_the_api(): void
    {
        config()->set('password-policy.mfa.driver', FakeMfaDriver::class);
        FakeMfaDriver::$enrolled = [];
        FakeMfaDriver::$challenges = 0;
        $user = $this->user();
        $as = fn () => $this->actingAs($user, 'web')->withToken('tok');

        $as()->getJson($this->url('mfa/status'))
            ->assertOk()
            ->assertJsonPath('data.driver_available', true)
            ->assertJsonPath('data.built_in', false)
            ->assertJsonPath('data.enrolled', false);

        $as()->postJson($this->url('mfa/challenge'))->assertStatus(409)->assertJsonPath('error', 'mfa_not_enrolled');

        FakeMfaDriver::$enrolled[$user->id] = true;

        $as()->postJson($this->url('mfa/challenge'))->assertOk();
        $this->assertSame(1, FakeMfaDriver::$challenges);

        $as()->postJson($this->url('mfa/verify'), ['code' => '000000'])->assertUnprocessable();
        $as()->postJson($this->url('mfa/verify'), ['code' => '123456'])->assertOk();
        $as()->getJson($this->url('mfa/status'))->assertJsonPath('data.verified', true);
    }

    public function test_set_up_and_recovery_codes_are_left_to_a_custom_driver(): void
    {
        config()->set('password-policy.mfa.driver', FakeMfaDriver::class);
        $this->enableTotp(); // even with the built-in app on, the host driver wins
        $user = $this->user();

        $this->actingAs($user, 'web')->postJson($this->url('mfa/enroll'))
            ->assertNotFound()->assertJsonPath('error', 'mfa_external_driver');
        $this->actingAs($user, 'web')->postJson($this->url('mfa/recovery-codes'), ['password' => 'Secret@123'])
            ->assertNotFound()->assertJsonPath('error', 'mfa_external_driver');
    }

    public function test_every_mfa_endpoint_is_404_without_any_driver(): void
    {
        $user = $this->user();

        foreach (['mfa/challenge', 'mfa/verify'] as $path) {
            $this->actingAs($user, 'web')->postJson($this->url($path), ['code' => '1'])
                ->assertNotFound()->assertJsonPath('error', 'mfa_disabled');
        }
    }

    // --- recovery codes and stateless MFA -----------------------------------------------

    public function test_recovery_codes_need_a_verified_token_and_the_password(): void
    {
        $this->enableTotp();
        $user = $this->user();
        $secret = $this->enrol($user, 2);
        $as = fn () => $this->actingAs($user, 'web')->withToken('tok');

        $as()->postJson($this->url('mfa/recovery-codes'), ['password' => 'Secret@123'])
            ->assertForbidden()->assertJsonPath('error', 'mfa_required');

        $as()->postJson($this->url('mfa/verify'), ['code' => (new Totp())->code($secret)])->assertOk();

        $as()->postJson($this->url('mfa/recovery-codes'), ['password' => 'wrong'])
            ->assertUnprocessable()->assertJsonValidationErrors('password');

        $codes = $as()->postJson($this->url('mfa/recovery-codes'), ['password' => 'Secret@123'])
            ->assertOk()->json('data.recovery_codes');

        $this->assertCount((int) config('password-policy.totp.recovery_codes'), $codes);
        $as()->getJson($this->url('mfa/status'))->assertJsonPath('data.recovery_codes_remaining', count($codes));
    }

    public function test_a_recovery_code_passes_mfa_once(): void
    {
        $this->enableTotp();
        $user = $this->user();
        $secret = $this->enrol($user);
        $codes = $this->actingAs($user, 'web')->withToken('a')
            ->postJson($this->url('mfa/verify'), ['code' => (new Totp())->code($secret)]);
        $codes->assertOk();

        $plain = $this->actingAs($user, 'web')->withToken('a')
            ->postJson($this->url('mfa/recovery-codes'), ['password' => 'Secret@123'])->json('data.recovery_codes');

        $this->actingAs($user, 'web')->withToken('b')->postJson($this->url('mfa/verify'), ['code' => $plain[0]])->assertOk();
        $this->actingAs($user, 'web')->withToken('c')->postJson($this->url('mfa/verify'), ['code' => $plain[0]])->assertUnprocessable();
    }

    public function test_admin_endpoints_need_mfa_verified_on_the_same_token(): void
    {
        $this->enableTotp();
        $admin = $this->admin(['role' => 'ADMIN']);
        $secret = $this->enrol($admin);
        $get = fn (string $token) => $this->actingAs($admin, 'web')->withToken($token)->getJson($this->url('admin/compliance'));

        $get('a')->assertForbidden()->assertJsonPath('error', 'mfa_required');

        $this->actingAs($admin, 'web')->withToken('a')
            ->postJson($this->url('mfa/verify'), ['code' => (new Totp())->code($secret)])->assertOk();

        $get('a')->assertOk();
        $get('b')->assertForbidden()->assertJsonPath('error', 'mfa_required');
    }

    // --- tokens survive a password change, the others do not ----------------------------

    public function test_changing_your_password_keeps_only_the_current_token(): void
    {
        Schema::create('test_tokens', function ($table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
        });

        $user = TokenUser::create([
            'name' => 'T', 'email' => 'tok@example.com', 'password' => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);
        $mine = TestToken::create(['user_id' => $user->id]);
        TestToken::create(['user_id' => $user->id]);
        TestToken::create(['user_id' => $user->id]);
        $user->currentToken = $mine;

        $this->actingAs($user, 'web')->putJson($this->url('password'), [
            'current_password' => 'Secret@123',
            'password' => 'Brand#New9pass', 'password_confirmation' => 'Brand#New9pass',
        ])->assertOk();

        $this->assertSame([$mine->id], TestToken::pluck('id')->all());
        $this->assertTrue(Hash::check('Brand#New9pass', $user->fresh()->password));
    }

    public function test_admin_termination_revokes_every_token(): void
    {
        Schema::create('test_tokens', function ($table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
        });

        $admin = $this->admin();
        $target = TokenUser::create([
            'name' => 'T', 'email' => 'tok2@example.com', 'password' => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);
        TestToken::create(['user_id' => $target->id]);
        TestToken::create(['user_id' => $target->id]);

        // The API resolves the target through user_model, so point it at TokenUser.
        config()->set('password-policy.user_model', TokenUser::class);

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/terminate-sessions"))->assertOk();

        $this->assertSame(0, TestToken::count());
    }

    // --- locking and known logins --------------------------------------------------------

    public function test_admin_can_lock_an_account_and_unlocking_needs_a_verifier(): void
    {
        $admin = $this->admin();
        $target = $this->user();

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/lock"), ['reason' => 'suspected takeover'])
            ->assertOk()
            ->assertJsonPath('data.locked', true)
            ->assertJsonPath('data.lock_type', 'permanent');

        $this->assertDatabaseHas('password_audit_logs', ['event' => 'account_locked_by_admin', 'user_id' => $target->id]);

        $this->postJson($this->url('login/check'), ['email' => $target->email])->assertStatus(423);

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/unlock"))
            ->assertUnprocessable()->assertJsonValidationErrors('verified_by');

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/unlock"), ['verified_by' => 'Helpdesk 7'])
            ->assertOk()->assertJsonPath('data.locked', false);
    }

    public function test_known_logins_are_listed_without_the_network_hash(): void
    {
        $admin = $this->admin();
        $target = $this->user();
        KnownLogin::create([
            'user_id' => $target->id, 'prefix_hash' => str_repeat('a', 64), 'country' => 'BD',
            'first_seen_at' => now()->subDays(3), 'last_seen_at' => now(),
        ]);

        $response = $this->actingAs($admin, 'web')->getJson($this->url("admin/users/{$target->id}/known-logins"))
            ->assertOk()->assertJsonCount(1, 'data')->assertJsonPath('data.0.country', 'BD');

        $this->assertStringNotContainsString(str_repeat('a', 64), $response->getContent());
    }

    // --- service accounts ----------------------------------------------------------------

    protected function register($admin, $service, array $extra = []): void
    {
        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts'), $extra + [
            'user_id' => $service->id, 'owner' => 'ops', 'purpose' => 'backups', 'rotation_days' => 30,
        ])->assertCreated();
    }

    public function test_service_account_can_be_updated_and_removed(): void
    {
        $admin = $this->admin();
        $service = $this->user();
        $stranger = $this->user();

        $this->actingAs($admin, 'web')->putJson($this->url("admin/service-accounts/{$stranger->id}"), ['owner' => 'x'])
            ->assertNotFound()->assertJsonPath('error', 'not_a_service_account');

        $this->register($admin, $service);

        $this->actingAs($admin, 'web')
            ->putJson($this->url("admin/service-accounts/{$service->id}"), ['owner' => 'platform', 'rotation_days' => 7, 'known_by' => [5, 6]])
            ->assertOk()
            ->assertJsonPath('data.owner', 'platform')
            ->assertJsonPath('data.rotation_days', 7)
            ->assertJsonPath('data.known_by', [5, 6]);

        $account = ServiceAccount::first();
        $this->assertTrue($account->next_rotation_at->lessThanOrEqualTo(now()->addDays(7)->addMinute()));

        $this->actingAs($admin, 'web')->putJson($this->url("admin/service-accounts/{$service->id}"), ['owner' => ''])
            ->assertUnprocessable();

        $this->actingAs($admin, 'web')->deleteJson($this->url("admin/service-accounts/{$service->id}"))->assertOk();
        $this->assertSame(0, ServiceAccount::count());
        $this->actingAs($admin, 'web')->deleteJson($this->url("admin/service-accounts/{$service->id}"))->assertNotFound();
    }

    public function test_rotation_goes_to_the_vault_and_the_secret_is_never_returned(): void
    {
        config()->set('password-policy.service_accounts.vault', RecordingVault::class);
        RecordingVault::$stored = [];
        $admin = $this->admin();
        $service = $this->user();
        $this->register($admin, $service);
        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);

        $response = $this->actingAs($admin, 'web')->postJson($this->url("admin/service-accounts/{$service->id}/rotate"))->assertOk();

        $this->assertCount(1, RecordingVault::$stored);
        [$id, $secret] = RecordingVault::$stored[0];
        $this->assertSame($service->id, $id);
        $this->assertStringNotContainsString($secret, $response->getContent());
        $this->assertTrue(Hash::check($secret, $service->fresh()->password));
        $this->assertTrue(ServiceAccount::first()->next_rotation_at->isFuture());
    }

    public function test_rotate_due_rotates_every_overdue_account(): void
    {
        config()->set('password-policy.service_accounts.vault', RecordingVault::class);
        RecordingVault::$stored = [];
        $admin = $this->admin();
        $a = $this->user();
        $b = $this->user();
        $this->register($admin, $a);
        $this->register($admin, $b);
        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts/rotate-due'))
            ->assertOk()->assertJsonCount(2, 'data')->assertJsonPath('data.0.rotated', true)->assertJsonPath('data.1.rotated', true);

        $this->assertCount(2, RecordingVault::$stored);
    }

    public function test_overdue_rotation_notice_counts_the_people_told(): void
    {
        Mail::fake();
        $admin = $this->admin();
        $service = $this->user();
        $this->register($admin, $service, ['owner' => 'owner@example.com']);

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts/notify-due'))
            ->assertOk()->assertJsonPath('notified', 0); // nothing is due yet

        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);
        config()->set('password-policy.service_accounts.notify_recipients', ['security@example.com']);

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts/notify-due'))
            ->assertOk()->assertJsonPath('notified', 2);
    }

    public function test_notice_with_nobody_to_tell_sends_nothing(): void
    {
        $admin = $this->admin();
        $service = $this->user();
        $this->register($admin, $service); // owner "ops" is not an address
        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts/notify-due'))
            ->assertOk()->assertJsonPath('notified', 0);
    }
}
