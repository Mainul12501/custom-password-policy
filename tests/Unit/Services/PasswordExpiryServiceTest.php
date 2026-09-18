<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class PasswordExpiryServiceTest extends TestCase
{
    protected PasswordExpiryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new PasswordExpiryService();
    }

    public function test_password_changed_91_days_ago_is_expired(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(91),
        ]);

        $this->assertTrue($this->service->isExpired($user));
    }

    public function test_password_changed_89_days_ago_is_not_expired(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(89),
        ]);

        $this->assertFalse($this->service->isExpired($user));
    }

    public function test_null_password_changed_at_is_expired(): void
    {
        $user = User::create([
            'name'     => 'Test',
            'email'    => 'test@example.com',
            'password' => Hash::make('Secret@123'),
        ]);

        $this->assertTrue($this->service->isExpired($user));
    }

    public function test_disabled_expiry_returns_false(): void
    {
        config()->set('password-policy.expiry.enabled', false);

        $user = User::create([
            'name'     => 'Test',
            'email'    => 'test@example.com',
            'password' => Hash::make('Secret@123'),
        ]);

        $this->assertFalse($this->service->isExpired($user));
    }

    public function test_zero_days_disables_expiry(): void
    {
        config()->set('password-policy.expiry.days', 0);

        $user = User::create([
            'name'     => 'Test',
            'email'    => 'test@example.com',
            'password' => Hash::make('Secret@123'),
        ]);

        $this->assertFalse($this->service->isExpired($user));
    }

    public function test_custom_expiry_days(): void
    {
        config()->set('password-policy.expiry.days', 30);

        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(31),
        ]);

        $this->assertTrue($this->service->isExpired($user));

        $user2 = User::create([
            'name'                => 'Test2',
            'email'               => 'test2@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(29),
        ]);

        $this->assertFalse($this->service->isExpired($user2));
    }
}
