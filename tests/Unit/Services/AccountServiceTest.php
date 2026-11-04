<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Events\PasswordCompromised;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Services\AccountService;
use Mainul\PasswordPolicy\Services\SessionTerminator;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class AccountServiceTest extends TestCase
{
    protected function user(): User
    {
        return User::create([
            'name'                => 'T',
            'email'               => 't@example.com',
            'password'            => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ]);
    }

    protected function accounts(): AccountService
    {
        return app(AccountService::class);
    }

    public function test_disable_marks_account_ends_sessions_and_audits(): void
    {
        $user = $this->user();

        $this->accounts()->disable($user, 'leaver', 'admin#1');

        $fresh = $user->fresh();
        $this->assertNotNull($fresh->disabled_at);
        $this->assertSame('leaver', $fresh->disabled_reason);
        $this->assertSame(1, (int) $fresh->session_version);

        $log = PasswordAuditLog::where('event', 'account_disabled')->firstOrFail();
        $this->assertSame(['reason' => 'leaver', 'actor' => 'admin#1'], $log->context);
    }

    public function test_disable_is_idempotent(): void
    {
        $user = $this->user();

        $this->accounts()->disable($user, 'leaver');
        $this->accounts()->disable($user->fresh(), 'leaver');

        $this->assertSame(1, PasswordAuditLog::where('event', 'account_disabled')->count());
        $this->assertSame(1, (int) $user->fresh()->session_version);
    }

    public function test_enable_clears_flags_and_forces_a_password_change(): void
    {
        $user = $this->user();
        $this->accounts()->disable($user, 'password_expired');

        $this->accounts()->enable($user->fresh(), 'admin#1');

        $fresh = $user->fresh();
        $this->assertNull($fresh->disabled_at);
        $this->assertNull($fresh->disabled_reason);
        $this->assertTrue($fresh->mustChangePassword());
    }

    public function test_mark_compromised_kills_password_and_sessions(): void
    {
        Event::fake([PasswordCompromised::class]);
        $user = $this->user();

        $this->accounts()->markCompromised($user, 'security-team');

        $fresh = $user->fresh();
        $this->assertFalse(Hash::check('Secret@123', $fresh->password), 'old password no longer works');
        $this->assertTrue($fresh->mustChangePassword());
        $this->assertGreaterThanOrEqual(1, (int) $fresh->session_version);
        $this->assertSame(1, $fresh->passwordHistories()->count());
        $this->assertSame(1, PasswordAuditLog::where('event', 'forced_reset')->count());

        Event::assertDispatched(PasswordCompromised::class, fn ($e) => $e->reportedBy === 'security-team');
    }

    public function test_session_terminator_bumps_version_and_rotates_remember_token(): void
    {
        $user = $this->user();
        $user->forceFill(['remember_token' => 'old-token'])->saveQuietly();

        app(SessionTerminator::class)->terminate($user->fresh());

        $fresh = $user->fresh();
        $this->assertSame(1, (int) $fresh->session_version);
        $this->assertNotSame('old-token', $fresh->remember_token);
    }

    public function test_session_terminator_deletes_database_sessions_of_the_user_only(): void
    {
        config()->set('session.driver', 'database');
        $user = $this->user();
        $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => Hash::make('x')]);

        foreach ([['s1', $user->id], ['s2', $user->id], ['s3', $other->id]] as [$id, $uid]) {
            DB::table('sessions')->insert(['id' => $id, 'user_id' => $uid, 'payload' => '', 'last_activity' => time()]);
        }

        app(SessionTerminator::class)->terminate($user->fresh());

        $this->assertSame(['s3'], DB::table('sessions')->pluck('id')->all());
    }

    public function test_every_termination_is_audited_with_its_reason(): void
    {
        app(SessionTerminator::class)->terminate($this->user(), false, 'manual');

        $log = PasswordAuditLog::where('event', 'sessions_terminated')->firstOrFail();
        $this->assertSame(['reason' => 'manual'], $log->context);
    }
}
