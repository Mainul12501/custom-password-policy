<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Rules;

use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Tests\TestCase;

class PasswordPolicyRuleTest extends TestCase
{
    protected PasswordPolicyRule $rule;

    protected function setUp(): void
    {
        parent::setUp();
        $this->rule = new PasswordPolicyRule();
    }

    public function test_valid_password_passes(): void
    {
        $this->assertTrue($this->rule->passes('password', 'Secret@123'));
    }

    public function test_password_without_uppercase_fails(): void
    {
        $this->assertFalse($this->rule->passes('password', 'secret@123'));
        $this->assertStringContainsString('uppercase', $this->rule->message());
    }

    public function test_password_without_lowercase_fails(): void
    {
        $this->assertFalse($this->rule->passes('password', 'SECRET@123'));
        $this->assertStringContainsString('lowercase', $this->rule->message());
    }

    public function test_password_without_number_fails(): void
    {
        $this->assertFalse($this->rule->passes('password', 'Secret@abc'));
        $this->assertStringContainsString('number', $this->rule->message());
    }

    public function test_password_without_special_character_fails(): void
    {
        $this->assertFalse($this->rule->passes('password', 'Secret123'));
        $this->assertStringContainsString('special', $this->rule->message());
    }

    public function test_password_too_short_fails(): void
    {
        $this->assertFalse($this->rule->passes('password', 'Se@1'));
        $this->assertStringContainsString('characters', $this->rule->message());
    }

    public function test_multiple_failures_listed_in_message(): void
    {
        $this->assertFalse($this->rule->passes('password', 'abc'));
        $message = $this->rule->message();
        $this->assertStringContainsString('characters', $message);
        $this->assertStringContainsString('uppercase', $message);
        $this->assertStringContainsString('number', $message);
        $this->assertStringContainsString('special', $message);
    }

    public function test_disabled_uppercase_rule_skips_check(): void
    {
        config()->set('password-policy.rules.require_uppercase', false);

        $this->assertTrue($this->rule->passes('password', 'secret@123'));
    }

    public function test_disabled_lowercase_rule_skips_check(): void
    {
        config()->set('password-policy.rules.require_lowercase', false);

        $this->assertTrue($this->rule->passes('password', 'SECRET@123'));
    }

    public function test_disabled_numeric_rule_skips_check(): void
    {
        config()->set('password-policy.rules.require_numeric', false);

        $this->assertTrue($this->rule->passes('password', 'Secret@abc'));
    }

    public function test_disabled_special_rule_skips_check(): void
    {
        config()->set('password-policy.rules.require_special', false);

        $this->assertTrue($this->rule->passes('password', 'Secret123'));
    }

    public function test_custom_min_length(): void
    {
        config()->set('password-policy.rules.min_length', 12);

        $this->assertFalse($this->rule->passes('password', 'Secret@1'));
        $this->assertTrue($this->rule->passes('password', 'SecretPass@12'));
    }

    public function test_validate_method_calls_fail_on_invalid(): void
    {
        $failed = false;

        $this->rule->validate('password', 'weak', function ($message) use (&$failed) {
            $failed = true;
            $this->assertIsString($message);
        });

        $this->assertTrue($failed);
    }

    public function test_validate_method_does_not_call_fail_on_valid(): void
    {
        $failed = false;

        $this->rule->validate('password', 'Secret@123', function () use (&$failed) {
            $failed = true;
        });

        $this->assertFalse($failed);
    }
}
