<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Rules;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Mainul\PasswordPolicy\Rules\CurrentPasswordRule;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class CurrentPasswordRuleTest extends TestCase
{
    protected function user(array $attrs = []): User
    {
        return User::create(array_merge([
            'name'                => 'T',
            'email'               => 't@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ], $attrs));
    }

    public function test_correct_current_password_passes(): void
    {
        $this->assertTrue((new CurrentPasswordRule($this->user()))->passes('current_password', 'Current@123'));
    }

    public function test_wrong_or_empty_current_password_fails(): void
    {
        $rule = new CurrentPasswordRule($this->user());

        $this->assertFalse($rule->passes('current_password', 'Wrong@123'));
        $this->assertFalse($rule->passes('current_password', ''));
        $this->assertFalse($rule->passes('current_password', null));
    }

    public function test_skipped_when_user_has_temporary_password(): void
    {
        $rule = new CurrentPasswordRule($this->user(['must_change_password' => true]));

        $this->assertTrue($rule->passes('current_password', ''));
    }

    public function test_skipped_when_password_expired(): void
    {
        $rule = new CurrentPasswordRule($this->user(['password_changed_at' => now()->subDays(200)]));

        $this->assertTrue($rule->passes('current_password', 'anything'));
    }

    public function test_skip_can_be_disabled(): void
    {
        config()->set('password-policy.current_password.skip_when_forced', false);
        config()->set('password-policy.current_password.skip_when_expired', false);

        $rule = new CurrentPasswordRule($this->user(['must_change_password' => true, 'password_changed_at' => now()->subDays(200)]));

        $this->assertFalse($rule->passes('current_password', 'anything'));
    }

    public function test_works_in_validator(): void
    {
        $user = $this->user();

        $this->assertTrue(Validator::make(['p' => 'Current@123'], ['p' => [new CurrentPasswordRule($user)]])->passes());
        $this->assertTrue(Validator::make(['p' => 'nope'], ['p' => [new CurrentPasswordRule($user)]])->fails());
    }
}
