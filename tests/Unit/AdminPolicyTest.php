<?php

namespace Mainul\PasswordPolicy\Tests\Unit;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Services\AccountClassifier;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;
use Mainul\PasswordPolicy\Support\ComplianceChecker;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class AdminPolicyTest extends TestCase
{
    protected function user(string $role, string $email, array $attrs = []): User
    {
        return User::create(array_merge([
            'name'                => 'T',
            'email'               => $email,
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
            'role'                => $role,
        ], $attrs));
    }

    public function test_classifier_recognises_admin_roles_and_flag(): void
    {
        $classifier = app(AccountClassifier::class);

        $this->assertTrue($classifier->isAdmin($this->user('Admin', 'a@example.com')));
        $this->assertTrue($classifier->isAdmin($this->user('super_admin', 'b@example.com')));
        $this->assertFalse($classifier->isAdmin($this->user('staff', 'c@example.com')));
        $this->assertFalse($classifier->isAdmin($this->user('', 'd@example.com')));
    }

    public function test_admin_needs_a_longer_password(): void
    {
        $admin = $this->user('admin', 'a@example.com');
        $staff = $this->user('staff', 'b@example.com');
        $twelve = 'Abcdef@12345';

        $this->assertTrue(PasswordPolicyRule::for($staff)->passes('p', $twelve));
        $this->assertFalse(PasswordPolicyRule::for($admin)->passes('p', $twelve));
        $this->assertTrue(PasswordPolicyRule::for($admin)->passes('p', $twelve . 'xy'));
    }

    public function test_admin_message_states_the_stricter_length(): void
    {
        $rule = PasswordPolicyRule::for($this->user('admin', 'a@example.com'));
        $rule->passes('p', 'Abcdef@12345');

        $this->assertStringContainsString('at least 14 characters', $rule->message());
    }

    public function test_rule_without_a_user_and_the_validator_alias_use_global_rules(): void
    {
        $this->assertTrue((new PasswordPolicyRule())->passes('p', 'Abcdef@12345'));
        $this->assertTrue(Validator::make(['p' => 'Abcdef@12345'], ['p' => 'password_policy'])->passes());
    }

    public function test_admin_settings_never_loosen_a_stricter_global_policy(): void
    {
        config()->set('password-policy.rules.min_length', 16);
        $admin = $this->user('admin', 'a@example.com');

        $this->assertFalse(PasswordPolicyRule::for($admin)->passes('p', 'Abcdef@12345678'), '15 chars');
        $this->assertTrue(PasswordPolicyRule::for($admin)->passes('p', 'Abcdef@1234567890'));
    }

    public function test_admin_passwords_expire_sooner(): void
    {
        $service = app(PasswordExpiryService::class);
        $admin = $this->user('admin', 'a@example.com', ['password_changed_at' => now()->subDays(70)]);
        $staff = $this->user('staff', 'b@example.com', ['password_changed_at' => now()->subDays(70)]);

        $this->assertTrue($service->isExpired($admin), '60 day admin limit');
        $this->assertFalse($service->isExpired($staff), '90 day normal limit');
    }

    public function test_admin_expiry_cannot_extend_a_shorter_global_limit(): void
    {
        config()->set('password-policy.expiry.days', 30);
        $admin = $this->user('admin', 'a@example.com', ['password_changed_at' => now()->subDays(40)]);

        $this->assertTrue(app(PasswordExpiryService::class)->isExpired($admin));
    }

    public function test_disabled_expiry_stays_disabled_for_admins(): void
    {
        config()->set('password-policy.expiry.days', 0);
        $admin = $this->user('admin', 'a@example.com', ['password_changed_at' => now()->subDays(500)]);

        $this->assertFalse(app(PasswordExpiryService::class)->isExpired($admin));
    }

    public function test_admins_get_a_longer_password_history(): void
    {
        $admin = $this->user('admin', 'a@example.com');
        $staff = $this->user('staff', 'b@example.com');

        foreach ([$admin, $staff] as $user) {
            foreach (['Old@Pass1', 'Old@Pass2', 'Old@Pass3', 'Old@Pass4'] as $i => $old) {
                PasswordHistory::create(['user_id' => $user->id, 'password' => Hash::make($old)])
                    ->forceFill(['created_at' => now()->subDays(10 - $i)])->save();
            }
        }

        $history = app(PasswordHistoryService::class);

        // Old@Pass1 is the 4th most recent previous password.
        $this->assertFalse($history->hasBeenUsed($staff, 'Old@Pass1'), 'normal users remember 3 (current + 2)');
        $this->assertTrue($history->hasBeenUsed($admin, 'Old@Pass1'), 'admins remember 5');
    }

    public function test_compliance_check_for_admin_separation(): void
    {
        $checker = new ComplianceChecker();
        $this->assertSame('warn', $checker->adminSeparation()[1]);

        config()->set('password-policy.admin.daily_email_domains', ['gmail.com']);
        $this->user('admin', 'boss@example.com');
        $this->user('staff', 'person@gmail.com');
        $this->assertSame('pass', $checker->adminSeparation()[1]);

        $bad = $this->user('admin', 'root@gmail.com');
        $result = $checker->adminSeparation();
        $this->assertSame('fail', $result[1]);
        $this->assertStringContainsString((string) $bad->id, $result[2]);
    }
}
