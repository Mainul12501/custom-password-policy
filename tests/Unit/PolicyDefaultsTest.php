<?php

namespace Mainul\PasswordPolicy\Tests\Unit;

use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

/**
 * PCP/01 section 2 and 3: shipped defaults and the "don't" checks.
 */
class PolicyDefaultsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Restore the shipped defaults.
        $defaults = require __DIR__ . '/../../config/password-policy.php';
        config()->set('password-policy.rules', $defaults['rules']);
        config()->set('password-policy.expiry.days', $defaults['expiry']['days']);
        config()->set('password-policy.history.max_reuse_count', $defaults['history']['max_reuse_count']);
    }

    public function test_shipped_defaults_match_the_policy(): void
    {
        $this->assertSame(11, config('password-policy.rules.min_length'));
        $this->assertSame(30, config('password-policy.expiry.days'));
        $this->assertSame(5, config('password-policy.history.max_reuse_count'));
    }

    public function test_ten_characters_fail_and_eleven_pass(): void
    {
        $rule = new PasswordPolicyRule();

        $this->assertFalse($rule->passes('p', 'Kx9#mTq2vL'));   // 10
        $this->assertTrue($rule->passes('p', 'Kx9#mTq2vLz'));   // 11
    }

    public function test_company_name_and_common_words_are_rejected(): void
    {
        $rule = new PasswordPolicyRule();

        $this->assertFalse($rule->passes('p', 'Remark#Kx9mTq2'));
        $this->assertFalse($rule->passes('p', 'My-PASSWORD#Kx92'));
    }

    public function test_repeated_and_sequential_characters_are_rejected(): void
    {
        $rule = new PasswordPolicyRule();

        $this->assertFalse($rule->passes('p', 'Kx#mTq2aaaaV'));
        $this->assertFalse($rule->passes('p', 'Kx#mTq2V1234'));
        $this->assertFalse($rule->passes('p', 'Kx#mTqdcbaV9'));
        $this->assertTrue($rule->passes('p', 'Kx#mTq2V13z8'));
    }

    public function test_personal_information_is_rejected_only_with_a_user(): void
    {
        $user = new User();
        $user->forceFill([
            'name'  => 'Rahim Uddin',
            'email' => 'rahim.uddin@example.com',
            'phone' => '+880 1712-345678',
        ]);

        $this->assertFalse(PasswordPolicyRule::for($user)->passes('p', 'Rahim#Kx9mTq2'));
        $this->assertFalse(PasswordPolicyRule::for($user)->passes('p', 'Kx#mTq2V01712345678'));
        $this->assertTrue(PasswordPolicyRule::for($user)->passes('p', 'Kx#mTq2V13z8'));
        $this->assertTrue((new PasswordPolicyRule())->passes('p', 'Rahim#Kx9mTq2'));
    }

    public function test_personal_info_check_can_be_disabled(): void
    {
        config()->set('password-policy.rules.forbid_personal_info', false);
        $user = new User();
        $user->forceFill(['name' => 'Rahim Uddin']);

        $this->assertTrue(PasswordPolicyRule::for($user)->passes('p', 'Rahim#Kx9mTq2'));
    }
}
