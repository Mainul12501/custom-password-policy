<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Rules;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Rules\PasswordNotReusedRule;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class PasswordNotReusedRuleTest extends TestCase
{
    public function test_current_password_is_rejected(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);

        $rule = new PasswordNotReusedRule($user);

        $this->assertFalse($rule->passes('password', 'Secret@123'));
    }

    public function test_password_in_history_is_rejected(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        PasswordHistory::create([
            'user_id'  => $user->id,
            'password' => Hash::make('OldPass@123'),
        ]);

        $rule = new PasswordNotReusedRule($user);

        $this->assertFalse($rule->passes('password', 'OldPass@123'));
    }

    public function test_new_password_is_accepted(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        $rule = new PasswordNotReusedRule($user);

        $this->assertTrue($rule->passes('password', 'BrandNew@456'));
    }

    public function test_old_password_beyond_limit_is_accepted(): void
    {
        config()->set('password-policy.history.max_reuse_count', 2);

        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        // This is old enough to be beyond the limit (max_reuse_count=2 means check current + 1 history)
        PasswordHistory::create([
            'user_id'    => $user->id,
            'password'   => Hash::make('VeryOld@123'),
            'created_at' => now()->subDays(200),
        ]);

        // This is the most recent history entry
        PasswordHistory::create([
            'user_id'    => $user->id,
            'password'   => Hash::make('Recent@123'),
            'created_at' => now()->subDays(10),
        ]);

        $rule = new PasswordNotReusedRule($user);

        // VeryOld@123 is beyond the limit, so it should be accepted
        $this->assertTrue($rule->passes('password', 'VeryOld@123'));

        // Recent@123 is within the limit
        $this->assertFalse($rule->passes('password', 'Recent@123'));
    }

    public function test_disabled_history_allows_reuse(): void
    {
        config()->set('password-policy.history.enabled', false);

        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);

        $rule = new PasswordNotReusedRule($user);

        $this->assertTrue($rule->passes('password', 'Secret@123'));
    }

    public function test_error_message_includes_count(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);

        $rule = new PasswordNotReusedRule($user);

        $this->assertStringContainsString('3', $rule->message());
    }
}
