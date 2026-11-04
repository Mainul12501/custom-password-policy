<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Rules\CanSelfResetPassword;
use Mainul\PasswordPolicy\Services\ResetEligibility;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class SelfResetRestrictionTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['web', 'password.block_self_reset'])->post('/forgot-password', fn () => response()->json(['sent' => true]));
    }

    protected function user(?string $role, string $email = 't@example.com'): User
    {
        return User::create([
            'name'     => 'T',
            'email'    => $email,
            'password' => Hash::make('Secret@123'),
            'role'     => $role,
        ]);
    }

    public function test_default_restricted_roles_are_ba_and_so_case_insensitive(): void
    {
        $eligibility = app(ResetEligibility::class);

        $this->assertFalse($eligibility->canSelfReset($this->user('BA', 'a@example.com')));
        $this->assertFalse($eligibility->canSelfReset($this->user('so', 'b@example.com')));
        $this->assertTrue($eligibility->canSelfReset($this->user('admin', 'c@example.com')));
        $this->assertTrue($eligibility->canSelfReset($this->user(null, 'd@example.com')));
    }

    public function test_restricted_roles_are_configurable(): void
    {
        config()->set('password-policy.reset.restricted_roles', ['intern']);

        $this->assertFalse(app(ResetEligibility::class)->canSelfReset($this->user('Intern')));
        $this->assertTrue(app(ResetEligibility::class)->canSelfReset($this->user('BA', 'x@example.com')));
    }

    public function test_role_attribute_name_is_configurable(): void
    {
        config()->set('password-policy.reset.role_attribute', 'name');
        $user = User::create(['name' => 'SO', 'email' => 'n@example.com', 'password' => Hash::make('x')]);

        $this->assertFalse(app(ResetEligibility::class)->canSelfReset($user));
    }

    public function test_role_resolver_supports_multiple_roles(): void
    {
        config()->set('password-policy.reset.role_resolver', MultiRoleResolver::class);

        $this->assertFalse(app(ResetEligibility::class)->canSelfReset($this->user('admin')));
    }

    public function test_middleware_blocks_restricted_role_with_json_403_and_audits(): void
    {
        $user = $this->user('BA');

        $this->postJson('/forgot-password', ['email' => 't@example.com'])
            ->assertStatus(403)
            ->assertJson(['error' => 'self_reset_not_allowed']);

        $log = PasswordAuditLog::where('event', 'password_reset_requested')->firstOrFail();
        $this->assertSame('blocked', $log->outcome);
        $this->assertSame($user->id, $log->user_id);
        $this->assertSame(['reason' => 'restricted_role'], $log->context);
    }

    public function test_middleware_redirects_back_with_an_error_for_web_requests(): void
    {
        $this->user('SO');

        $this->post('/forgot-password', ['email' => 't@example.com'])
            ->assertRedirect()
            ->assertSessionHasErrors('email');
    }

    public function test_other_roles_and_unknown_emails_pass_through(): void
    {
        $this->user('admin');

        $this->postJson('/forgot-password', ['email' => 't@example.com'])->assertOk();
        $this->postJson('/forgot-password', ['email' => 'ghost@example.com'])->assertOk();
        $this->postJson('/forgot-password', [])->assertOk();
        $this->assertSame(0, PasswordAuditLog::count());
    }

    public function test_validation_rule(): void
    {
        $this->user('BA');
        $this->user('admin', 'ok@example.com');

        $fails = fn (string $email) => Validator::make(['email' => $email], ['email' => [new CanSelfResetPassword()]])->fails();

        $this->assertTrue($fails('t@example.com'));
        $this->assertFalse($fails('ok@example.com'));
        $this->assertFalse($fails('ghost@example.com'));
    }
}

class MultiRoleResolver
{
    public function __invoke(Authenticatable $user): array
    {
        return ['staff', 'so'];
    }
}
