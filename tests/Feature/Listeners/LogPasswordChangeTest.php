<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Listeners;

use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\PasswordHistory;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class LogPasswordChangeTest extends TestCase
{
    public function test_password_change_creates_history_record(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('OldPass@123'),
            'password_changed_at' => now()->subDays(10),
        ]);

        $oldHash = $user->password;

        $user->password = Hash::make('NewPass@456');
        $user->save();

        $this->assertDatabaseHas('password_histories', [
            'user_id'  => $user->id,
            'password' => $oldHash,
        ]);
    }

    public function test_password_change_updates_password_changed_at(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('OldPass@123'),
            'password_changed_at' => now()->subDays(100),
        ]);

        $user->password = Hash::make('NewPass@456');
        $user->save();

        $user->refresh();

        $this->assertTrue($user->password_changed_at->isToday());
    }

    public function test_non_password_update_does_not_create_history(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);

        $user->name = 'Updated Name';
        $user->save();

        $this->assertDatabaseCount('password_histories', 0);
    }

    public function test_multiple_password_changes_create_multiple_records(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Pass@001'),
            'password_changed_at' => now(),
        ]);

        $user->password = Hash::make('Pass@002');
        $user->save();

        $user->password = Hash::make('Pass@003');
        $user->save();

        $this->assertDatabaseCount('password_histories', 2);
        $this->assertEquals(2, PasswordHistory::where('user_id', $user->id)->count());
    }

    public function test_password_history_relationship(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Pass@001'),
            'password_changed_at' => now(),
        ]);

        $user->password = Hash::make('Pass@002');
        $user->save();

        $this->assertCount(1, $user->passwordHistories);
    }

    public function test_password_expired_helper(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now()->subDays(91),
        ]);

        $this->assertTrue($user->passwordExpired());

        $user->password_changed_at = now();
        $user->saveQuietly();

        $this->assertFalse($user->passwordExpired());
    }

    public function test_has_used_password_helper(): void
    {
        $user = User::create([
            'name'                => 'Test',
            'email'               => 'test@example.com',
            'password'            => Hash::make('Current@123'),
            'password_changed_at' => now(),
        ]);

        $this->assertTrue($user->hasUsedPassword('Current@123'));
        $this->assertFalse($user->hasUsedPassword('BrandNew@456'));
    }
}
