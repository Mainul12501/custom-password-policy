<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Mainul\PasswordPolicy\Support\ComplianceChecker;
use Mainul\PasswordPolicy\Tests\Support\ExposedUser;
use Mainul\PasswordPolicy\Tests\TestCase;

class CheckCommandTest extends TestCase
{
    protected function useProductionEnv(): void
    {
        $this->app['env'] = 'production';
        $this->beforeApplicationDestroyed(fn () => $this->app['env'] = 'testing');
    }

    public function test_hashing_driver_check(): void
    {
        config()->set('hashing.driver', 'bcrypt');
        $this->assertSame('pass', (new ComplianceChecker())->hashingDriver()[1]);

        config()->set('hashing.driver', 'md5');
        $this->assertSame('fail', (new ComplianceChecker())->hashingDriver()[1]);
    }

    public function test_production_without_tls_enforcement_fails(): void
    {
        $this->useProductionEnv();
        config()->set('password-policy.tls.enforce', false);

        $this->assertSame('fail', (new ComplianceChecker())->transport()[1]);
    }

    public function test_tls_is_not_required_outside_production(): void
    {
        $this->assertSame('pass', (new ComplianceChecker())->transport()[1]);
    }

    public function test_reset_link_expiry_check(): void
    {
        config()->set('auth.passwords.users.expire', 60);
        $this->assertSame('pass', (new ComplianceChecker())->resetLinkExpiry()[1]);

        config()->set('auth.passwords.users.expire', 180);
        $check = (new ComplianceChecker())->resetLinkExpiry();
        $this->assertSame('fail', $check[1]);
        $this->assertStringContainsString('users (180 min)', $check[2]);

        config()->set('password-policy.reset.max_expire_minutes', 240);
        $this->assertSame('pass', (new ComplianceChecker())->resetLinkExpiry()[1]);
    }

    public function test_hidden_password_check_detects_exposed_model(): void
    {
        $this->assertSame('pass', (new ComplianceChecker())->hiddenPassword()[1]);

        config()->set('password-policy.user_model', ExposedUser::class);
        $this->assertSame('fail', (new ComplianceChecker())->hiddenPassword()[1]);
    }

    public function test_command_runs_and_reports_failure_for_bad_hashing(): void
    {
        config()->set('hashing.driver', 'md5');

        $this->artisan('password-policy:check')->assertFailed();
    }

    public function test_command_succeeds_with_defaults(): void
    {
        $this->artisan('password-policy:check')->assertSuccessful();
    }
}
