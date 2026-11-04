<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Middleware;

use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Services\MfaService;
use Mainul\PasswordPolicy\Support\ComplianceChecker;
use Mainul\PasswordPolicy\Tests\Support\FakeMfaDriver;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class RequireMfaTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        FakeMfaDriver::$enrolled = [];
        FakeMfaDriver::$challenges = 0;

        Route::middleware(['web', 'password.mfa'])->get('/secure', fn () => response()->json(['ok' => true]));
        Route::middleware(['web', 'password.mfa'])->get('/mfa', fn () => response()->json(['challenge' => true]))->name('mfa.challenge');
        Route::middleware(['web'])->get('/login-again', function (Request $request) {
            Event::dispatch(new Login('web', $request->user(), false));

            return response()->json(['flag' => session(MfaService::SESSION_KEY)]);
        });
    }

    protected function useDriver(): void
    {
        config()->set('password-policy.mfa.driver', FakeMfaDriver::class);
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

    public function test_guest_and_ordinary_user_are_not_asked_for_mfa(): void
    {
        $this->getJson('/secure')->assertOk();
        $this->actingAs($this->user())->getJson('/secure')->assertOk();
    }

    public function test_admin_is_blocked_when_no_driver_is_configured(): void
    {
        $this->actingAs($this->user('admin'))->getJson('/secure')
            ->assertStatus(403)
            ->assertJson(['error' => 'mfa_unavailable']);
    }

    public function test_admin_role_match_ignores_case(): void
    {
        $this->actingAs($this->user('Super_Admin'))->getJson('/secure')->assertStatus(403);
    }

    public function test_admin_flag_attribute_also_marks_an_admin(): void
    {
        config()->set('password-policy.admin.flag_attribute', 'phone');
        $user = $this->user();
        $user->forceFill(['phone' => '1'])->saveQuietly();

        $this->actingAs($user)->getJson('/secure')->assertStatus(403);
    }

    public function test_admin_must_enrol_then_verify(): void
    {
        $this->useDriver();
        $admin = $this->user('admin');

        $this->actingAs($admin)->getJson('/secure')
            ->assertStatus(403)->assertJson(['error' => 'mfa_enrollment_required']);

        FakeMfaDriver::$enrolled[$admin->id] = true;

        $this->actingAs($admin)->getJson('/secure')
            ->assertStatus(403)->assertJson(['error' => 'mfa_required']);

        $this->actingAs($admin)->withSession([MfaService::SESSION_KEY => $admin->id])
            ->getJson('/secure')->assertOk();
    }

    public function test_verification_of_another_user_does_not_count(): void
    {
        $this->useDriver();
        $admin = $this->user('admin');
        FakeMfaDriver::$enrolled[$admin->id] = true;

        $this->actingAs($admin)->withSession([MfaService::SESSION_KEY => $admin->id + 99])
            ->getJson('/secure')->assertStatus(403);
    }

    public function test_challenge_route_stays_reachable_for_admins(): void
    {
        $this->useDriver();
        $admin = $this->user('admin');
        FakeMfaDriver::$enrolled[$admin->id] = true;

        $this->actingAs($admin)->getJson('/mfa')->assertOk();
    }

    public function test_web_requests_are_redirected_to_the_challenge_route(): void
    {
        $this->useDriver();
        $admin = $this->user('admin');
        FakeMfaDriver::$enrolled[$admin->id] = true;

        $this->actingAs($admin)->get('/secure')->assertRedirect(route('mfa.challenge'));
    }

    public function test_require_all_covers_standard_users(): void
    {
        $this->useDriver();
        config()->set('password-policy.mfa.require_all', true);

        $this->actingAs($this->user())->getJson('/secure')->assertStatus(403);
    }

    public function test_remote_requests_need_mfa_only_with_known_internal_networks(): void
    {
        $this->useDriver();
        $user = $this->user();

        // No internal networks configured: cannot tell, so not required.
        $this->actingAs($user)->getJson('/secure')->assertOk();

        config()->set('password-policy.mfa.internal_networks', ['10.0.0.0/8']);
        $this->actingAs($user)->withServerVariables(['REMOTE_ADDR' => '10.1.2.3'])->getJson('/secure')->assertOk();
        $this->actingAs($user)->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->getJson('/secure')
            ->assertStatus(403)->assertJson(['error' => 'mfa_enrollment_required']);

        config()->set('password-policy.mfa.require_remote', false);
        $this->actingAs($user)->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->getJson('/secure')->assertOk();
    }

    public function test_a_new_login_clears_the_verified_flag(): void
    {
        $user = $this->user();

        $this->actingAs($user)->withSession([MfaService::SESSION_KEY => $user->id])
            ->getJson('/login-again')
            ->assertJson(['flag' => null]);
    }

    public function test_service_verify_marks_session_and_audits(): void
    {
        $this->useDriver();
        $admin = $this->user('admin');
        FakeMfaDriver::$enrolled[$admin->id] = true;
        $service = app(MfaService::class);

        $request = Request::create('/x');
        $request->setLaravelSession(app('session.store'));

        $this->assertFalse($service->verify($admin, '000000', $request));
        $this->assertFalse($service->isVerified($admin, $request));

        $this->assertTrue($service->verify($admin, '123456', $request));
        $this->assertTrue($service->isVerified($admin, $request));

        $service->forget($request);
        $this->assertFalse($service->isVerified($admin, $request));

        $this->assertSame(
            ['failure', 'success'],
            PasswordAuditLog::where('event', 'mfa_verified')->orderBy('id')->pluck('outcome')->all()
        );
    }

    public function test_unenrolled_user_cannot_verify_even_with_a_valid_code(): void
    {
        $this->useDriver();
        $admin = $this->user('admin');
        $request = Request::create('/x');
        $request->setLaravelSession(app('session.store'));

        $this->assertFalse(app(MfaService::class)->verify($admin, '123456', $request));
    }

    public function test_challenge_is_delegated_and_audited(): void
    {
        $this->useDriver();

        app(MfaService::class)->challenge($this->user('admin'));

        $this->assertSame(1, FakeMfaDriver::$challenges);
        $this->assertSame(1, PasswordAuditLog::where('event', 'mfa_challenge')->count());
    }

    public function test_compliance_check_reports_the_driver_state(): void
    {
        $this->assertSame('warn', (new ComplianceChecker())->mfaConfigured()[1]);

        $this->useDriver();
        $this->assertSame('pass', (new ComplianceChecker())->mfaConfigured()[1]);

        config()->set('password-policy.mfa.driver', \stdClass::class);
        $this->assertSame('fail', (new ComplianceChecker())->mfaConfigured()[1]);
    }
}
