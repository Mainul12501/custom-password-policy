<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Api;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Mfa\Totp;
use Mainul\PasswordPolicy\Models\MfaCredential;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\SettingsRepository;
use Mainul\PasswordPolicy\Tests\Support\FakeSmsChannel;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class ApiTest extends TestCase
{
    protected const BASE = '/api/password-policy';

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('password-policy.api.enabled', true);
        config()->set('password-policy.api.guard', 'web');
        config()->set('password-policy.temporary_password.channels.mail', FakeSmsChannel::class);
        FakeSmsChannel::$texts = [];
        FakeSmsChannel::$sent = [];
    }

    protected function user(array $attrs = []): User
    {
        static $n = 0;
        $n++;

        return User::create(array_merge([
            'name'     => 'Test User',
            'email'    => "user{$n}@example.com",
            'phone'    => '01700000000',
            'password' => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ], $attrs));
    }

    /** Signed-in admin who is allowed every API ability. */
    protected function admin(array $attrs = []): User
    {
        foreach (config('password-policy.api.abilities') as $ability) {
            Gate::define($ability, fn () => true);
        }
        Gate::define(config('password-policy.audit.gate_ability'), fn () => true);

        return $this->user($attrs + ['email' => 'boss@example.com']);
    }

    protected function url(string $path): string
    {
        return self::BASE . '/' . ltrim($path, '/');
    }

    // --- switch and authentication -------------------------------------------

    public function test_api_is_404_while_disabled(): void
    {
        config()->set('password-policy.api.enabled', false);

        $this->postJson($this->url('login/check'), ['email' => 'a@b.c'])
            ->assertNotFound()
            ->assertJsonPath('error', 'api_disabled');
    }

    public function test_database_setting_switches_the_api_on_over_config(): void
    {
        config()->set('password-policy.api.enabled', false);
        app(SettingsRepository::class)->set('api.enabled', true, 'tester');

        $this->postJson($this->url('login/check'), ['email' => 'nobody@example.com'])->assertOk();
    }

    public function test_protected_routes_need_authentication(): void
    {
        $this->getJson($this->url('policy'))->assertUnauthorized()->assertJsonPath('error', 'unauthenticated');
    }

    public function test_unknown_guard_in_config_is_reported_not_crashed(): void
    {
        config()->set('password-policy.api.guard', 'nope');

        $this->getJson($this->url('policy'))->assertStatus(500)->assertJsonPath('error', 'api_guard_misconfigured');
    }

    public function test_database_guard_overrides_config_guard(): void
    {
        config()->set('password-policy.api.guard', 'nope');
        app(SettingsRepository::class)->set('api.guard', 'web');

        $this->actingAs($this->user(), 'web')->getJson($this->url('policy'))->assertOk();
    }

    public function test_guard_setting_rejects_unknown_guards(): void
    {
        $this->expectException(InvalidArgumentException::class);

        app(SettingsRepository::class)->set('api.guard', 'does-not-exist');
    }

    public function test_guard_can_be_a_list_and_the_first_match_wins(): void
    {
        config()->set('password-policy.api.guard', 'nope,web');

        // The unknown guard is reported before the list is exhausted.
        $this->actingAs($this->user(), 'web')->getJson($this->url('policy'))->assertStatus(500);

        config()->set('password-policy.api.guard', ['web']);
        $this->actingAs($this->user(), 'web')->getJson($this->url('policy'))->assertOk();
    }

    // --- own password -----------------------------------------------------------

    public function test_policy_does_not_disclose_the_banned_word_list(): void
    {
        config()->set('password-policy.rules.banned_words', ['secretword']);

        $response = $this->actingAs($this->user(), 'web')->getJson($this->url('policy'))->assertOk();

        $response->assertJsonPath('data.has_banned_words', true);
        $this->assertStringNotContainsString('secretword', $response->getContent());
    }

    public function test_status_reports_expiry(): void
    {
        $user = $this->user(['password_changed_at' => now()->subDays(90)->subHour()]);

        $this->actingAs($user, 'web')->getJson($this->url('password/status'))
            ->assertOk()
            ->assertJsonPath('data.expired', true)
            ->assertJsonPath('data.mfa.required', false);
    }

    public function test_validate_lists_the_failures_without_changing_anything(): void
    {
        $user = $this->user();

        $this->actingAs($user, 'web')->postJson($this->url('password/validate'), ['password' => 'short'])
            ->assertOk()
            ->assertJsonPath('valid', false)
            ->assertJsonCount(1, 'errors');

        $this->actingAs($user, 'web')->postJson($this->url('password/validate'), ['password' => 'Brand#New9pass'])
            ->assertOk()
            ->assertJsonPath('valid', true);

        $this->assertTrue(Hash::check('Secret@123', $user->fresh()->password));
    }

    public function test_change_password_requires_the_current_password(): void
    {
        $user = $this->user();
        $payload = ['password' => 'Brand#New9pass', 'password_confirmation' => 'Brand#New9pass'];

        // Omitting the field must not skip the check.
        $this->actingAs($user, 'web')->putJson($this->url('password'), $payload)
            ->assertUnprocessable()->assertJsonValidationErrors('current_password');

        $this->actingAs($user, 'web')->putJson($this->url('password'), $payload + ['current_password' => 'wrong'])
            ->assertUnprocessable()->assertJsonValidationErrors('current_password');

        $this->assertTrue(Hash::check('Secret@123', $user->fresh()->password));

        $this->actingAs($user, 'web')->putJson($this->url('password'), $payload + ['current_password' => 'Secret@123'])
            ->assertOk();

        $this->assertTrue(Hash::check('Brand#New9pass', $user->fresh()->password));
        $this->assertSame(1, $user->passwordHistories()->count());
    }

    public function test_change_password_enforces_the_policy_and_history(): void
    {
        $user = $this->user();
        $weak = ['current_password' => 'Secret@123', 'password' => 'weakpass', 'password_confirmation' => 'weakpass'];

        $this->actingAs($user, 'web')->putJson($this->url('password'), $weak)
            ->assertUnprocessable()->assertJsonValidationErrors('password');

        $same = ['current_password' => 'Secret@123', 'password' => 'Secret@123', 'password_confirmation' => 'Secret@123'];
        $user->update(['password' => Hash::make('Secret@123')]); // put the current hash into history
        $user->update(['password' => Hash::make('Other#Pass99')]);

        $this->actingAs($user->fresh(), 'web')
            ->putJson($this->url('password'), ['current_password' => 'Other#Pass99'] + array_diff_key($same, ['current_password' => 1]))
            ->assertUnprocessable()->assertJsonValidationErrors('password');
    }

    public function test_forced_change_does_not_ask_for_the_current_password(): void
    {
        $user = $this->user(['must_change_password' => true]);

        $this->actingAs($user, 'web')
            ->putJson($this->url('password'), ['password' => 'Brand#New9pass', 'password_confirmation' => 'Brand#New9pass'])
            ->assertOk();

        $this->assertFalse((bool) $user->fresh()->must_change_password);
    }

    // --- before login -------------------------------------------------------------

    public function test_login_check_blocks_a_locked_account(): void
    {
        $user = $this->user();

        $this->postJson($this->url('login/check'), ['email' => $user->email])->assertOk()->assertJsonPath('allowed', true);

        for ($i = 0; $i < 5; $i++) {
            app(LockoutService::class)->recordFailure($user->fresh());
        }

        $this->postJson($this->url('login/check'), ['email' => $user->email])
            ->assertStatus(423)
            ->assertJsonPath('error', 'account_unavailable');
    }

    public function test_reset_code_answers_the_same_for_every_account(): void
    {
        $known = $this->user();
        $message = $this->postJson($this->url('reset/code'), ['email' => 'nobody@example.com'])
            ->assertStatus(202)->json('message');

        $this->postJson($this->url('reset/code'), ['email' => $known->email])
            ->assertStatus(202)->assertJsonPath('message', $message);

        $this->assertCount(1, FakeSmsChannel::$texts);
    }

    public function test_restricted_roles_get_no_reset_code(): void
    {
        $user = $this->user(['role' => 'BA']);

        $this->postJson($this->url('reset/code'), ['email' => $user->email])->assertStatus(202);

        $this->assertCount(0, FakeSmsChannel::$texts);
    }

    public function test_reset_with_a_valid_code_sets_the_password(): void
    {
        $user = $this->user();
        $this->postJson($this->url('reset/code'), ['email' => $user->email]);
        preg_match('/code is (\d+)/', end(FakeSmsChannel::$texts)[1], $m);

        $this->postJson($this->url('reset/password'), [
            'email' => $user->email, 'code' => $m[1],
            'password' => 'Brand#New9pass', 'password_confirmation' => 'Brand#New9pass',
        ])->assertOk();

        $this->assertTrue(Hash::check('Brand#New9pass', $user->fresh()->password));

        // The code works once.
        $this->postJson($this->url('reset/password'), [
            'email' => $user->email, 'code' => $m[1],
            'password' => 'Another#Pass77', 'password_confirmation' => 'Another#Pass77',
        ])->assertUnprocessable()->assertJsonPath('error', 'reset_invalid');
    }

    public function test_reset_fails_the_same_way_for_a_wrong_code_and_an_unknown_email(): void
    {
        $user = $this->user();
        $this->postJson($this->url('reset/code'), ['email' => $user->email]);
        $body = ['code' => '000000', 'password' => 'Brand#New9pass', 'password_confirmation' => 'Brand#New9pass'];

        $wrong = $this->postJson($this->url('reset/password'), $body + ['email' => $user->email])->assertUnprocessable();
        $unknown = $this->postJson($this->url('reset/password'), $body + ['email' => 'nobody@example.com'])->assertUnprocessable();

        $this->assertSame($wrong->json(), $unknown->json());
        $this->assertTrue(Hash::check('Secret@123', $user->fresh()->password));
    }

    // --- authenticator app ----------------------------------------------------------

    protected function enableTotp(): void
    {
        config()->set('password-policy.totp.enabled', true);
        config()->set('password-policy.totp.grace_days', 0);
    }

    public function test_mfa_endpoints_are_404_while_totp_is_off(): void
    {
        $this->actingAs($this->user(), 'web')->postJson($this->url('mfa/enroll'))->assertNotFound();
    }

    public function test_user_can_enrol_and_confirm_an_authenticator_app(): void
    {
        $this->enableTotp();
        $user = $this->user();

        $setup = $this->actingAs($user, 'web')->postJson($this->url('mfa/enroll'))
            ->assertOk()->assertJsonStructure(['data' => ['secret', 'uri']]);

        $this->actingAs($user, 'web')->postJson($this->url('mfa/enroll/confirm'), ['code' => '000000'])
            ->assertUnprocessable();

        $code = (new Totp())->code($setup->json('data.secret'));
        $confirmed = $this->actingAs($user, 'web')->postJson($this->url('mfa/enroll/confirm'), ['code' => $code])
            ->assertOk();

        $this->assertNotEmpty($confirmed->json('data.recovery_codes'));

        // An enrolled factor is not replaced from a password-only token.
        $this->actingAs($user, 'web')->postJson($this->url('mfa/enroll'))->assertStatus(409);
    }

    public function test_mfa_verified_state_follows_the_bearer_token(): void
    {
        $this->enableTotp();
        $user = $this->user();
        $secret = (new Totp())->generateSecret();
        MfaCredential::create(['user_id' => $user->id, 'secret' => $secret, 'confirmed_at' => now(), 'recovery_codes' => []]);

        $status = fn (string $token) => $this->actingAs($user, 'web')->withToken($token)
            ->getJson($this->url('mfa/status'))->json('data.verified');

        $this->assertFalse($status('token-a'));

        $this->actingAs($user, 'web')->withToken('token-a')
            ->postJson($this->url('mfa/verify'), ['code' => (new Totp())->code($secret)])
            ->assertOk()->assertJsonPath('verified', true);

        $this->assertTrue($status('token-a'));
        $this->assertFalse($status('token-b'), 'another token has not passed MFA');
    }

    public function test_admin_endpoints_demand_mfa_when_configured(): void
    {
        $this->enableTotp();
        $admin = $this->admin(['role' => 'ADMIN']);

        $this->actingAs($admin, 'web')->withToken('t')->getJson($this->url('admin/compliance'))
            ->assertForbidden()->assertJsonPath('error', 'mfa_enrollment_required');
    }

    // --- administration -------------------------------------------------------------

    public function test_admin_actions_are_denied_until_the_gate_is_defined(): void
    {
        $target = $this->user();

        $this->actingAs($this->user(['email' => 'x@example.com']), 'web')
            ->postJson($this->url("admin/users/{$target->id}/disable"))
            ->assertForbidden();
    }

    public function test_admin_can_disable_and_enable_an_account(): void
    {
        $admin = $this->admin();
        $target = $this->user();

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/disable"), ['reason' => 'investigation'])
            ->assertOk()->assertJsonPath('data.disabled', true)->assertJsonPath('data.disabled_reason', 'investigation');

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/enable"))
            ->assertOk()->assertJsonPath('data.disabled', false)->assertJsonPath('data.must_change_password', true);

        $this->assertDatabaseHas('password_audit_logs', ['event' => 'account_disabled', 'user_id' => $target->id]);
    }

    public function test_user_resource_never_exposes_secrets(): void
    {
        $admin = $this->admin();
        $target = $this->user();

        $response = $this->actingAs($admin, 'web')->getJson($this->url("admin/users/{$target->id}"))->assertOk();

        $this->assertStringNotContainsString($target->password, $response->getContent());
        $response->assertJsonMissingPath('data.password');
    }

    public function test_unlocking_a_permanent_lock_needs_the_verifier(): void
    {
        $admin = $this->admin();
        $target = $this->user(['is_permanently_locked' => true, 'requires_identity_verification' => true]);

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/unlock"))
            ->assertUnprocessable()->assertJsonValidationErrors('verified_by');

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/unlock"), ['verified_by' => 'Helpdesk 7'])
            ->assertOk()->assertJsonPath('data.locked', false);
    }

    public function test_compromise_makes_the_old_password_unusable(): void
    {
        $admin = $this->admin();
        $target = $this->user();

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/compromise"))
            ->assertOk()->assertJsonPath('data.must_change_password', true);

        $this->assertFalse(Hash::check('Secret@123', $target->fresh()->password));
    }

    public function test_temporary_password_is_delivered_but_never_returned(): void
    {
        $admin = $this->admin();
        $target = $this->user();

        $response = $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/temporary-password"))
            ->assertOk()->assertJsonPath('channel', 'sms');

        $sent = FakeSmsChannel::$sent[0][1];
        $this->assertStringNotContainsString($sent, $response->getContent());
        $this->assertTrue(Hash::check($sent, $target->fresh()->password));
        $this->assertTrue((bool) $target->fresh()->must_change_password);
    }

    public function test_temporary_password_without_a_secure_channel_changes_nothing(): void
    {
        $admin = $this->admin();
        $target = $this->user(['phone' => null]);

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/temporary-password"))
            ->assertUnprocessable()->assertJsonPath('error', 'no_secure_channel');

        $this->assertTrue(Hash::check('Secret@123', $target->fresh()->password));
    }

    public function test_admin_can_terminate_sessions_and_reset_mfa(): void
    {
        $this->enableTotp();
        config()->set('password-policy.totp.scope', 'admins'); // the acting (non-admin) user needs no MFA
        $admin = $this->admin();
        $target = $this->user();
        MfaCredential::create(['user_id' => $target->id, 'secret' => 'ABC', 'confirmed_at' => now(), 'recovery_codes' => []]);

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$target->id}/terminate-sessions"))->assertOk();
        $this->assertSame(1, (int) $target->fresh()->session_version);

        $this->actingAs($admin, 'web')->deleteJson($this->url("admin/users/{$target->id}/mfa"))->assertOk();
        $this->assertSame(0, MfaCredential::count());
    }

    public function test_offboarding_lists_the_passwords_to_rotate(): void
    {
        $admin = $this->admin();
        $leaver = $this->user();
        $service = $this->user();

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts'), [
            'user_id' => $service->id, 'owner' => 'ops', 'purpose' => 'backups', 'known_by' => [$leaver->id],
        ])->assertCreated();

        $this->actingAs($admin, 'web')->postJson($this->url("admin/users/{$leaver->id}/offboard"))
            ->assertOk()
            ->assertJsonPath('user.disabled', true)
            ->assertJsonPath('rotation_required.0.user_id', $service->id);
    }

    public function test_service_accounts_can_be_registered_listed_and_rotation_needs_a_vault(): void
    {
        $admin = $this->admin();
        $service = $this->user();

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts'), ['user_id' => $service->id])
            ->assertUnprocessable();

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts'), [
            'user_id' => $service->id, 'owner' => 'ops', 'purpose' => 'backups', 'rotation_days' => 30,
        ])->assertCreated()->assertJsonPath('data.rotation_days', 30);

        $this->actingAs($admin, 'web')->getJson($this->url('admin/service-accounts'))->assertJsonCount(1, 'data');

        ServiceAccount::query()->update(['next_rotation_at' => now()->subDay()]);
        $this->actingAs($admin, 'web')->getJson($this->url('admin/service-accounts?due=1'))->assertJsonCount(1, 'data');

        $this->actingAs($admin, 'web')->postJson($this->url("admin/service-accounts/{$service->id}/rotate"))
            ->assertUnprocessable()->assertJsonPath('error', 'rotation_refused');

        $this->actingAs($admin, 'web')->postJson($this->url('admin/service-accounts/rotate-due'))
            ->assertOk()->assertJsonPath('data.0.rotated', false);
    }

    public function test_settings_can_be_changed_and_reset(): void
    {
        $admin = $this->admin();

        $data = $this->actingAs($admin, 'web')
            ->putJson($this->url('admin/settings'), ['settings' => ['totp.enabled' => true, 'totp.scope' => 'admins']])
            ->assertOk()->json('data');

        $this->assertTrue($data['totp.enabled']['value']);
        $this->assertSame('database', $data['totp.enabled']['source']);

        $this->assertNotNull(app(SettingsRepository::class)->get('totp.enabled_at'));

        $data = $this->actingAs($admin, 'web')->deleteJson($this->url('admin/settings/totp.scope'))
            ->assertOk()->json('data');
        $this->assertSame('config', $data['totp.scope']['source']);

        $this->actingAs($admin, 'web')->putJson($this->url('admin/settings'), ['settings' => ['totp.enabled' => false]])->assertOk();
        $this->assertFalse(app(SettingsRepository::class)->has('totp.enabled_at'));
    }

    public function test_a_bad_setting_changes_nothing(): void
    {
        $admin = $this->admin();

        $this->actingAs($admin, 'web')
            ->putJson($this->url('admin/settings'), ['settings' => ['totp.scope' => 'admins', 'api.guard' => 'does-not-exist']])
            ->assertUnprocessable();

        $this->assertFalse(app(SettingsRepository::class)->has('totp.scope'));

        $this->actingAs($admin, 'web')
            ->putJson($this->url('admin/settings'), ['settings' => ['password.rules' => 1]])
            ->assertUnprocessable();
    }

    public function test_admin_can_switch_the_api_guard_from_the_database(): void
    {
        $admin = $this->admin();

        $data = $this->actingAs($admin, 'web')->putJson($this->url('admin/settings'), ['settings' => ['api.guard' => 'web']])
            ->assertOk()->json('data');

        $this->assertSame('database', $data['api.guard']['source']);
    }

    public function test_audit_log_is_filterable_and_paginated(): void
    {
        $admin = $this->admin();
        PasswordAuditLog::create(['event' => 'login', 'outcome' => 'success', 'user_id' => 99]);
        PasswordAuditLog::create(['event' => 'login', 'outcome' => 'failure', 'user_id' => 99]);

        $this->actingAs($admin, 'web')->getJson($this->url('admin/audit?outcome=failure&user_id=99'))
            ->assertOk()->assertJsonPath('total', 1)->assertJsonPath('data.0.outcome', 'failure');

        $this->actingAs($admin, 'web')->getJson($this->url('admin/audit?outcome=bogus'))->assertUnprocessable();
    }

    public function test_audit_log_uses_its_own_gate(): void
    {
        $admin = $this->admin();
        Gate::define(config('password-policy.audit.gate_ability'), fn () => false);

        $this->actingAs($admin, 'web')->getJson($this->url('admin/audit'))->assertForbidden();
    }

    public function test_compliance_reports_the_self_test(): void
    {
        $admin = $this->admin();

        $this->actingAs($admin, 'web')->getJson($this->url('admin/compliance'))
            ->assertOk()
            ->assertJsonStructure(['passed', 'counts' => ['pass', 'warn', 'fail'], 'data' => [['check', 'status', 'detail']]]);
    }

    public function test_default_password_scan_for_one_user_and_for_everyone(): void
    {
        $admin = $this->admin();
        $weak = $this->user(['password' => Hash::make('Password1')]);
        $this->user();

        $this->actingAs($admin, 'web')->postJson($this->url('admin/compliance/default-passwords'), ['user_id' => $weak->id, 'flag' => true])
            ->assertOk()->assertJsonPath('found.0.id', $weak->id);
        $this->assertTrue((bool) $weak->fresh()->must_change_password);

        $started = $this->actingAs($admin, 'web')->postJson($this->url('admin/compliance/default-passwords'))
            ->assertStatus(202);

        // The test queue runs jobs inline.
        $this->actingAs($admin, 'web')->getJson($this->url('admin/compliance/default-passwords/' . $started->json('scan_id')))
            ->assertOk()->assertJsonPath('status', 'finished')->assertJsonCount(1, 'found');

        $this->actingAs($admin, 'web')->getJson($this->url('admin/compliance/default-passwords/unknown'))->assertNotFound();
    }

    public function test_disable_expired_supports_a_dry_run(): void
    {
        $admin = $this->admin();
        $stale = $this->user(['password_changed_at' => now()->subDays(200)]);

        $this->actingAs($admin, 'web')->postJson($this->url('admin/accounts/disable-expired'), ['dry_run' => true])
            ->assertOk()->assertJsonPath('count', 1);
        $this->assertNull($stale->fresh()->disabled_at);

        $this->actingAs($admin, 'web')->postJson($this->url('admin/accounts/disable-expired'))
            ->assertOk()->assertJsonPath('count', 1);
        $this->assertNotNull($stale->fresh()->disabled_at);
    }

    public function test_disabled_callers_are_turned_away(): void
    {
        $user = $this->user(['disabled_at' => now(), 'disabled_reason' => 'leaver']);

        $this->actingAs($user, 'web')->getJson($this->url('policy'))
            ->assertForbidden()->assertJsonPath('error', 'account_disabled');
    }
}
