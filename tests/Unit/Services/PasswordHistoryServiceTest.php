<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class PasswordHistoryServiceTest extends TestCase
{
    protected PasswordHistoryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new PasswordHistoryService();
    }

    public function test_current_password_is_detected(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        $this->assertTrue($this->service->hasBeenUsed($user, 'Current@123'));
    }

    public function test_password_in_history_is_detected(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        PasswordHistory::create([
            'user_id'  => $user->id,
            'password' => Hash::make('Old@Pass1'),
        ]);

        $this->assertTrue($this->service->hasBeenUsed($user, 'Old@Pass1'));
    }

    public function test_new_password_is_not_detected(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        $this->assertFalse($this->service->hasBeenUsed($user, 'BrandNew@456'));
    }

    public function test_respects_max_reuse_count(): void
    {
        config()->set('password-policy.history.max_reuse_count', 2);

        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        // Older history entry (beyond limit)
        PasswordHistory::create([
            'user_id'    => $user->id,
            'password'   => Hash::make('VeryOld@123'),
            'created_at' => now()->subDays(200),
        ]);

        // Recent history entry (within limit)
        PasswordHistory::create([
            'user_id'    => $user->id,
            'password'   => Hash::make('Recent@123'),
            'created_at' => now()->subDays(10),
        ]);

        // VeryOld should not be checked (beyond max_reuse_count - 1 = 1 history record)
        $this->assertFalse($this->service->hasBeenUsed($user, 'VeryOld@123'));

        // Recent should be checked
        $this->assertTrue($this->service->hasBeenUsed($user, 'Recent@123'));
    }

    public function test_disabled_history_always_returns_false(): void
    {
        config()->set('password-policy.history.enabled', false);

        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        $this->assertFalse($this->service->hasBeenUsed($user, 'Current@123'));
    }

    public function test_zero_max_reuse_count_disables_check(): void
    {
        config()->set('password-policy.history.max_reuse_count', 0);

        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        $this->assertFalse($this->service->hasBeenUsed($user, 'Current@123'));
    }
}
