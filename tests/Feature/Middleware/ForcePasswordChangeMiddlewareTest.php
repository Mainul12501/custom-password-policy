<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class ForcePasswordChangeMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['password.force_change'])->get('/protected', fn () => response()->json(['message' => 'OK']));
        Route::middleware(['password.force_change'])->get('/password/change', fn () => response()->json(['message' => 'form']))->name('password.change');
    }

    protected function user(bool $forced): User
    {
        return User::create([
            'name'                 => 'T',
            'email'                => 't@example.com',
            'password'             => Hash::make('Secret@123'),
            'password_changed_at'  => now(),
            'must_change_password' => $forced,
        ]);
    }

    public function test_normal_user_passes(): void
    {
        $this->actingAs($this->user(false))->getJson('/protected')->assertOk();
    }

    public function test_guest_passes_through(): void
    {
        $this->getJson('/protected')->assertOk();
    }

    public function test_forced_user_is_blocked_with_json_403(): void
    {
        $this->actingAs($this->user(true))
            ->getJson('/protected')
            ->assertStatus(403)
            ->assertJson(['error' => 'password_change_required']);
    }

    public function test_forced_user_is_redirected_on_web_requests(): void
    {
        $this->actingAs($this->user(true))
            ->get('/protected')
            ->assertRedirect(route('password.change'));
    }

    public function test_forced_user_can_still_reach_the_change_page(): void
    {
        $this->actingAs($this->user(true))->getJson('/password/change')->assertOk();
    }
}
