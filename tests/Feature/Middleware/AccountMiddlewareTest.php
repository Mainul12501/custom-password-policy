<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\SessionTerminator;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class AccountMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['web', 'password.account_active'])->get('/active', fn () => response()->json(['ok' => true]));
        Route::middleware(['web', 'password.session_version'])->get('/versioned', fn () => response()->json(['ok' => true]));
        Route::middleware(['web', 'auth'])->post('/change', function () {
            $user = auth()->user();
            $user->password = Hash::make('Brand@New123');
            $user->save();

            return response()->json([
                'session' => session(SessionTerminator::SESSION_KEY),
                'db'      => (int) User::find($user->id)->session_version,
            ]);
        });
    }

    protected function user(array $attrs = []): User
    {
        return User::create(array_merge([
            'name'                => 'T',
            'email'               => 't@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ], $attrs));
    }

    public function test_guest_and_healthy_user_pass(): void
    {
        $this->getJson('/active')->assertOk();
        $this->actingAs($this->user())->getJson('/active')->assertOk();
    }

    public function test_disabled_user_is_blocked_and_signed_out(): void
    {
        $user = $this->user(['disabled_at' => now(), 'disabled_reason' => 'leaver']);

        $this->actingAs($user)->getJson('/active')
            ->assertStatus(403)
            ->assertJson(['error' => 'account_disabled']);

        $this->assertGuest();
    }

    public function test_web_request_of_disabled_user_gets_403(): void
    {
        $this->actingAs($this->user(['disabled_at' => now()]))->get('/active')->assertStatus(403);
    }

    public function test_locked_user_is_blocked(): void
    {
        $user = $this->user(['locked_until' => now()->addMinutes(5)]);

        $this->actingAs($user)->getJson('/active')
            ->assertStatus(403)
            ->assertJson(['error' => 'account_locked']);
    }

    public function test_user_past_the_grace_period_is_disabled_on_the_spot(): void
    {
        $user = $this->user(['password_changed_at' => now()->subDays(92)]);

        $this->actingAs($user)->getJson('/active')
            ->assertStatus(403)
            ->assertJson(['error' => 'account_disabled']);

        $fresh = $user->fresh();
        $this->assertNotNull($fresh->disabled_at);
        $this->assertSame('password_expired', $fresh->disabled_reason);
    }

    public function test_expired_user_inside_grace_period_is_not_disabled(): void
    {
        $user = $this->user(['password_changed_at' => now()->subDays(90)->subHours(2)]);

        $this->actingAs($user)->getJson('/active')->assertOk();
        $this->assertNull($user->fresh()->disabled_at);
    }

    public function test_session_with_old_version_is_rejected(): void
    {
        $user = $this->user();
        app(SessionTerminator::class)->terminate($user);

        $this->actingAs($user->fresh())
            ->withSession([SessionTerminator::SESSION_KEY => 0])
            ->getJson('/versioned')
            ->assertStatus(401)
            ->assertJson(['error' => 'session_terminated']);
    }

    public function test_session_with_current_version_passes(): void
    {
        $user = $this->user();
        app(SessionTerminator::class)->terminate($user);

        $this->actingAs($user->fresh())
            ->withSession([SessionTerminator::SESSION_KEY => 1])
            ->getJson('/versioned')
            ->assertOk();
    }

    public function test_session_without_stored_version_adopts_the_current_one(): void
    {
        $this->actingAs($this->user())->getJson('/versioned')->assertOk();
    }

    public function test_changing_own_password_ends_other_sessions_but_keeps_this_one(): void
    {
        $user = $this->user();

        $response = $this->actingAs($user)
            ->withSession([SessionTerminator::SESSION_KEY => 0])
            ->postJson('/change');

        $response->assertOk();
        $this->assertSame(1, $response->json('db'), 'version bumped, so other sessions are invalid');
        $this->assertSame(1, $response->json('session'), 'this session adopted the new version');
    }

    public function test_termination_on_password_change_can_be_turned_off(): void
    {
        config()->set('password-policy.sessions.terminate_on_password_change', false);
        $user = $this->user();

        $response = $this->actingAs($user)->postJson('/change');

        $this->assertSame(0, $response->json('db'));
    }

    public function test_lockout_service_state_is_visible_to_the_middleware_after_permanent_lock(): void
    {
        $user = $this->user();
        for ($i = 0; $i < 5; $i++) {
            app(LockoutService::class)->recordFailure($user->fresh(), '198.51.100.1');
        }

        $this->actingAs($user->fresh())->getJson('/active')->assertStatus(403);
    }
}
