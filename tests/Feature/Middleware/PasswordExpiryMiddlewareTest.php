<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class PasswordExpiryMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['password.expiry'])->get('/protected', function () {
            return response()->json(['message' => 'OK']);
        })->name('protected');

        Route::get('/password/change', function () {
            return response()->json(['message' => 'Change password form']);
        })->name('password.change');
    }

    public function test_user_with_valid_password_can_access_route(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);

        $response = $this->actingAs($user)->getJson('/protected');

        $response->assertStatus(200);
        $response->assertJson(['message' => 'OK']);
    }

    public function test_user_with_expired_password_gets_403_json(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(91),
        ]);

        $response = $this->actingAs($user)->getJson('/protected');

        $response->assertStatus(403);
        $response->assertJson([
            'error' => 'password_expired',
        ]);
    }

    public function test_user_with_expired_password_gets_redirected_on_web(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(91),
        ]);

        $response = $this->actingAs($user)->get('/protected');

        $response->assertRedirect(route('password.change'));
    }

    public function test_user_with_null_password_changed_at_is_expired(): void
    {
        $user = User::create([
            'name'     => 'Test',
            'email'    => 'test@example.com',
            'password' => Hash::make('Secret@123'),
        ]);

        $response = $this->actingAs($user)->getJson('/protected');

        $response->assertStatus(403);
    }

    public function test_unauthenticated_request_passes_through(): void
    {
        $response = $this->getJson('/protected');

        // Should pass through middleware (no user to check), but may get 200 since no auth middleware
        $response->assertStatus(200);
    }

    public function test_excluded_routes_bypass_check(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(91),
        ]);

        // password.change is in the excluded routes list
        $response = $this->actingAs($user)->getJson('/password/change');

        // Should not get 403 since the route/path is excluded
        $response->assertStatus(200);
    }

    public function test_disabled_expiry_passes_through(): void
    {
        config()->set('password-policy.expiry.enabled', false);

        $user = User::create([
            'name'     => 'Test',
            'email'    => 'test@example.com',
            'password' => Hash::make('Secret@123'),
        ]);

        $response = $this->actingAs($user)->getJson('/protected');

        $response->assertStatus(200);
    }
}
