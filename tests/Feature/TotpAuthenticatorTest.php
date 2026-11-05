<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Mfa\RecoveryCodes;
use Mainul\PasswordPolicy\Mfa\Totp;
use Mainul\PasswordPolicy\Models\MfaCredential;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Models\PolicySetting;
use Mainul\PasswordPolicy\Services\MfaService;
use Mainul\PasswordPolicy\Services\SettingsRepository;
use Mainul\PasswordPolicy\Services\TotpEnrollmentService;
use Mainul\PasswordPolicy\Support\ComplianceChecker;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class TotpAuthenticatorTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // Load the bundled routes (routes are registered at boot).
        $defaults = require __DIR__ . '/../../config/password-policy.php';
        $app['config']->set('password-policy.totp', array_merge($defaults['totp'], ['routes' => true]));
    }

    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['web', 'password.mfa'])->get('/secure', fn () => response()->json(['ok' => true]));
    }

    protected function enable(array $extra = []): void
    {
        config()->set('password-policy.totp.enabled', true);
        config()->set('password-policy.totp.grace_days', 0);

        foreach ($extra as $key => $value) {
            config()->set("password-policy.totp.{$key}", $value);
        }
    }

    protected function user(string $role = 'staff', string $email = 't@example.com'): User
    {
        return User::create([
            'name'     => 'T',
            'email'    => $email,
            'password' => Hash::make('Secret@123'),
            'role'     => $role,
        ]);
    }

    /** Enrolled user with a known secret. Returns [user, secret]. */
    protected function enrolled(string $role = 'staff', string $email = 't@example.com'): array
    {
        $user = $this->user($role, $email);
        $secret = (new Totp())->generateSecret();

        MfaCredential::create([
            'user_id'        => $user->id,
            'secret'         => $secret,
            'confirmed_at'   => now(),
            'recovery_codes' => RecoveryCodes::generate(2)['stored'],
        ]);

        return [$user, $secret];
    }

    protected function code(string $secret): string
    {
        return (new Totp())->code($secret);
    }

    // ---- off by default -------------------------------------------------

    public function test_nothing_changes_while_the_feature_is_off(): void
    {
        $user = $this->user();

        $this->actingAs($user)->getJson('/secure')->assertOk();
        $this->actingAs($user)->get('/mfa/enroll')->assertNotFound();
        $this->actingAs($user)->get('/mfa/challenge')->assertNotFound();
    }

    // ---- required once enabled ------------------------------------------

    public function test_unenrolled_user_is_sent_to_enrol_once_enabled(): void
    {
        $this->enable();
        $user = $this->user();

        $this->actingAs($user)->getJson('/secure')
            ->assertStatus(403)->assertJson(['error' => 'mfa_enrollment_required']);
        $this->actingAs($user)->get('/secure')->assertRedirect(route('mfa.enroll'));
    }

    public function test_enrolled_user_must_pass_the_challenge(): void
    {
        $this->enable();
        [$user] = $this->enrolled();

        $this->actingAs($user)->getJson('/secure')
            ->assertStatus(403)->assertJson(['error' => 'mfa_required']);
        $this->actingAs($user)->get('/secure')->assertRedirect(route('mfa.challenge'));
        $this->actingAs($user)->withSession([MfaService::SESSION_KEY => $user->id])
            ->getJson('/secure')->assertOk();
    }

    public function test_scope_admins_leaves_ordinary_users_alone(): void
    {
        $this->enable(['scope' => 'admins']);

        $this->actingAs($this->user())->getJson('/secure')->assertOk();
        $this->actingAs($this->user('admin', 'a@example.com'))->getJson('/secure')->assertStatus(403);
    }

    // ---- grace period ---------------------------------------------------

    public function test_unenrolled_users_may_sign_in_during_the_grace_period(): void
    {
        $this->enable(['grace_days' => 7]);
        app(SettingsRepository::class)->set('totp.enabled_at', now()->subDays(3)->toIso8601String());
        $user = $this->user();

        $this->actingAs($user)->getJson('/secure')->assertOk();

        app(SettingsRepository::class)->set('totp.enabled_at', now()->subDays(8)->toIso8601String());
        $this->actingAs($user)->getJson('/secure')->assertStatus(403);
    }

    public function test_grace_never_skips_the_challenge_for_enrolled_users(): void
    {
        $this->enable(['grace_days' => 7]);
        app(SettingsRepository::class)->set('totp.enabled_at', now()->toIso8601String());
        [$user] = $this->enrolled();

        $this->actingAs($user)->getJson('/secure')->assertStatus(403)->assertJson(['error' => 'mfa_required']);
    }

    // ---- enrolment ------------------------------------------------------

    public function test_user_can_enrol_with_a_code_from_the_app(): void
    {
        $this->enable();
        $user = $this->user();

        $this->actingAs($user)->get('/mfa/enroll')->assertOk()->assertSee('Key:');

        $credential = MfaCredential::where('user_id', $user->id)->first();
        $this->assertNull($credential->confirmed_at, 'unconfirmed until a code is proven');

        $response = $this->actingAs($user)->postJson('/mfa/enroll', ['code' => $this->code($credential->secret)]);

        $response->assertOk()->assertJsonCount(8, 'recovery_codes');
        $this->assertNotNull($credential->fresh()->confirmed_at);
        $this->assertSame(8, app(TotpEnrollmentService::class)->recoveryCodesRemaining($user));
        $this->assertTrue(PasswordAuditLog::where('event', 'mfa_enrolled')->exists());
    }

    public function test_enrolment_marks_the_session_verified(): void
    {
        $this->enable();
        $user = $this->user();
        $this->actingAs($user)->get('/mfa/enroll');
        $secret = MfaCredential::first()->secret;

        $this->actingAs($user)->post('/mfa/enroll', ['code' => $this->code($secret)])
            ->assertOk()
            ->assertSessionHas(MfaService::SESSION_KEY, $user->id);
    }

    public function test_wrong_code_does_not_confirm_enrolment(): void
    {
        $this->enable();
        $user = $this->user();
        $this->actingAs($user)->get('/mfa/enroll');

        $this->actingAs($user)->postJson('/mfa/enroll', ['code' => '000000'])->assertStatus(422);

        $this->assertNull(MfaCredential::first()->confirmed_at);
        $this->actingAs($user)->getJson('/secure')->assertStatus(403)->assertJson(['error' => 'mfa_enrollment_required']);
    }

    public function test_reloading_the_enrol_page_keeps_the_same_secret(): void
    {
        $this->enable();
        $user = $this->user();

        $this->actingAs($user)->get('/mfa/enroll');
        $first = MfaCredential::first()->secret;
        $this->actingAs($user)->get('/mfa/enroll');

        $this->assertSame($first, MfaCredential::first()->secret);
        $this->assertSame(1, MfaCredential::count());
    }

    public function test_secret_is_encrypted_at_rest(): void
    {
        [$user, $secret] = $this->enrolled();

        $raw = DB::table('mfa_credentials')->where('user_id', $user->id)->value('secret');

        $this->assertStringNotContainsString($secret, $raw);
        $this->assertSame($secret, MfaCredential::first()->secret);
    }

    public function test_an_enrolled_factor_cannot_be_replaced_from_a_password_only_session(): void
    {
        $this->enable();
        [$user, $secret] = $this->enrolled();

        $this->actingAs($user)->get('/mfa/enroll')->assertRedirect(route('mfa.challenge'));
        $this->actingAs($user)->postJson('/mfa/enroll', ['code' => $this->code($secret)])->assertForbidden();
        $this->assertSame($secret, MfaCredential::first()->secret);
    }

    // ---- challenge ------------------------------------------------------

    public function test_correct_code_passes_the_challenge(): void
    {
        $this->enable();
        [$user, $secret] = $this->enrolled();

        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $this->code($secret)])->assertOk();

        $this->actingAs($user)->post('/mfa/challenge', ['code' => $this->code($secret)])
            ->assertSessionHasErrors('code'); // same time-step: replay
    }

    public function test_session_is_marked_verified_after_a_correct_code(): void
    {
        $this->enable();
        [$user, $secret] = $this->enrolled();

        $this->actingAs($user)->post('/mfa/challenge', ['code' => $this->code($secret)])
            ->assertRedirect()
            ->assertSessionHas(MfaService::SESSION_KEY, $user->id);
    }

    public function test_wrong_code_is_rejected_and_audited(): void
    {
        $this->enable();
        [$user] = $this->enrolled();

        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => '123456'])->assertStatus(422);

        $this->assertTrue(PasswordAuditLog::where('event', 'mfa_verified')->where('outcome', 'failure')->exists());
    }

    public function test_a_used_code_cannot_be_replayed_but_the_next_one_works(): void
    {
        $this->enable();
        [$user, $secret] = $this->enrolled();
        Carbon::setTestNow('2026-01-01 12:00:00');

        $code = $this->code($secret);
        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $code])->assertOk();
        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $code])->assertStatus(422);

        Carbon::setTestNow('2026-01-01 12:00:31');
        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $this->code($secret)])->assertOk();

        Carbon::setTestNow();
    }

    public function test_an_expired_code_is_rejected(): void
    {
        $this->enable();
        [$user, $secret] = $this->enrolled();
        Carbon::setTestNow('2026-01-01 12:00:00');
        $old = (new Totp())->code($secret, Carbon::now()->subMinutes(5)->getTimestamp());

        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $old])->assertStatus(422);

        Carbon::setTestNow();
    }

    public function test_repeated_wrong_codes_lock_the_account(): void
    {
        $this->enable();
        [$user, $secret] = $this->enrolled();

        for ($i = 0; $i < 5; $i++) {
            $this->actingAs($user)->postJson('/mfa/challenge', ['code' => '000000']);
        }

        $this->assertTrue(app(\Mainul\PasswordPolicy\Services\LockoutService::class)->isLocked($user->fresh()));

        // Even the right code is refused while locked.
        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $this->code($secret)])->assertStatus(422);
        $this->assertNull(MfaCredential::first()->last_used_step);
    }

    public function test_recovery_code_works_once(): void
    {
        $this->enable();
        $user = $this->user();
        $codes = RecoveryCodes::generate(2);
        MfaCredential::create([
            'user_id'        => $user->id,
            'secret'         => (new Totp())->generateSecret(),
            'confirmed_at'   => now(),
            'recovery_codes' => $codes['stored'],
        ]);

        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $codes['plain'][0]])->assertOk();
        $this->actingAs($user)->postJson('/mfa/challenge', ['code' => $codes['plain'][0]])->assertStatus(422);
        $this->assertSame(1, app(TotpEnrollmentService::class)->recoveryCodesRemaining($user));
    }

    // ---- recovery code regeneration -------------------------------------

    public function test_regenerating_codes_needs_a_verified_session_and_the_password(): void
    {
        $this->enable();
        [$user] = $this->enrolled();

        $this->actingAs($user)->postJson('/mfa/recovery-codes', ['password' => 'Secret@123'])->assertForbidden();

        $verified = [MfaService::SESSION_KEY => $user->id];
        $this->actingAs($user)->withSession($verified)
            ->postJson('/mfa/recovery-codes', ['password' => 'wrong'])->assertStatus(422);
        $this->actingAs($user)->withSession($verified)
            ->postJson('/mfa/recovery-codes', ['password' => 'Secret@123'])
            ->assertOk()->assertJsonCount(8, 'recovery_codes');
    }

    // ---- settings: database vs config -----------------------------------

    public function test_database_override_beats_the_config_default(): void
    {
        $settings = app(SettingsRepository::class);
        $this->assertFalse($settings->get('totp.enabled'));

        $settings->set('totp.enabled', true, 'tester');

        $this->assertTrue($settings->get('totp.enabled'));
        $this->assertTrue(app(MfaService::class)->totpEnabled());
        $this->assertTrue(PasswordAuditLog::where('event', 'setting_changed')->exists());

        $settings->forget('totp.enabled', 'tester');
        $this->assertFalse($settings->get('totp.enabled'));
    }

    public function test_lock_to_config_stops_the_database_switching_it_off(): void
    {
        config()->set('password-policy.totp.enabled', true);
        config()->set('password-policy.totp.lock_to_config', true);

        app(SettingsRepository::class)->set('totp.enabled', false);

        $this->assertTrue(app(SettingsRepository::class)->get('totp.enabled'));
    }

    public function test_unknown_or_invalid_settings_are_refused(): void
    {
        $settings = app(SettingsRepository::class);

        $this->expectException(\InvalidArgumentException::class);
        $settings->set('rules.min_length', 3);
    }

    public function test_invalid_values_are_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        app(SettingsRepository::class)->set('totp.scope', 'everyone');
    }

    public function test_config_default_applies_when_the_settings_table_is_missing(): void
    {
        config()->set('password-policy.totp.enabled', true);
        \Illuminate\Support\Facades\Schema::drop('password_policy_settings');
        app(SettingsRepository::class)->flush();

        $this->assertTrue(app(SettingsRepository::class)->get('totp.enabled'));
    }

    // ---- command --------------------------------------------------------

    public function test_command_enables_and_disables_the_feature(): void
    {
        $this->artisan('password-policy:totp', ['--enable' => true, '--scope' => 'admins', '--grace-days' => 3, '--actor' => 'ops'])
            ->expectsOutputToContain('now required')
            ->assertSuccessful();

        $settings = app(SettingsRepository::class);
        $this->assertTrue($settings->get('totp.enabled'));
        $this->assertSame('admins', $settings->get('totp.scope'));
        $this->assertSame(3, $settings->get('totp.grace_days'));
        $this->assertNotNull($settings->get('totp.enabled_at'));

        $this->artisan('password-policy:totp', ['--disable' => true])->assertSuccessful();
        $this->assertFalse($settings->get('totp.enabled'));
        $this->assertNull(PolicySetting::find('totp.enabled_at'));
    }

    public function test_command_refuses_to_disable_a_locked_config(): void
    {
        config()->set('password-policy.totp.enabled', true);
        config()->set('password-policy.totp.lock_to_config', true);

        $this->artisan('password-policy:totp', ['--disable' => true])->assertFailed();
    }

    public function test_command_resets_a_lost_device(): void
    {
        [$user] = $this->enrolled();

        $this->artisan('password-policy:totp', ['--reset' => $user->email, '--actor' => 'ops'])->assertSuccessful();

        $this->assertSame(0, MfaCredential::count());
        $this->assertTrue(PasswordAuditLog::where('event', 'mfa_reset')->exists());
    }

    public function test_command_rejects_conflicting_or_bad_options(): void
    {
        $this->artisan('password-policy:totp', ['--enable' => true, '--disable' => true])->assertFailed();
        $this->artisan('password-policy:totp', ['--scope' => 'nobody'])->assertFailed();
        $this->artisan('password-policy:totp', ['--reset' => 'missing@example.com'])->assertFailed();
    }

    public function test_status_command_runs(): void
    {
        $this->artisan('password-policy:totp', ['--status' => true])->assertSuccessful();
    }

    // ---- compliance check -----------------------------------------------

    public function test_compliance_check_reports_unenrolled_users(): void
    {
        $checker = new ComplianceChecker();
        $this->assertSame('pass', $checker->totpEnrollment()[1]);

        $this->enable();
        $this->enrolled('staff', 'a@example.com');
        $this->user('staff', 'b@example.com');

        $result = $checker->totpEnrollment();
        $this->assertSame('warn', $result[1]);
        $this->assertStringContainsString('1 of 2', $result[2]);
        $this->assertSame('pass', $checker->mfaConfigured()[1]);
    }

    // ---- custom driver still wins ---------------------------------------

    public function test_a_configured_custom_driver_takes_over_from_the_built_in_one(): void
    {
        $this->enable();
        config()->set('password-policy.mfa.driver', \Mainul\PasswordPolicy\Tests\Support\FakeMfaDriver::class);

        $this->assertInstanceOf(
            \Mainul\PasswordPolicy\Tests\Support\FakeMfaDriver::class,
            app(MfaService::class)->driver()
        );
    }
}
