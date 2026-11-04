<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Logging\RedactSensitiveData;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Services\AuditLogger;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;
use Monolog\Handler\TestHandler;
use Monolog\Logger;

class AuditLogTest extends TestCase
{
    protected function user(): User
    {
        return User::create([
            'name'     => 'T',
            'email'    => 't@example.com',
            'password' => Hash::make('Secret@123'),
        ]);
    }

    public function test_successful_login_is_logged(): void
    {
        $user = $this->user();

        Event::dispatch(new Login('web', $user, false));

        $log = PasswordAuditLog::where('event', 'login_attempt')->firstOrFail();
        $this->assertSame('success', $log->outcome);
        $this->assertSame($user->id, $log->user_id);
        $this->assertSame('t@example.com', $log->identifier);
        $this->assertNotNull($log->created_at);
    }

    public function test_failed_login_logs_identifier_but_never_the_password(): void
    {
        Event::dispatch(new Failed('web', null, ['email' => 'ghost@example.com', 'password' => 'Hunter2!']));

        $log = PasswordAuditLog::where('event', 'login_attempt')->firstOrFail();
        $this->assertSame('failure', $log->outcome);
        $this->assertSame('ghost@example.com', $log->identifier);
        $this->assertNull($log->user_id);
        $this->assertStringNotContainsString('Hunter2!', json_encode($log->toArray()));
    }

    public function test_password_change_is_logged_via_trait(): void
    {
        $user = $this->user();

        $user->password = Hash::make('Another@456');
        $user->save();

        $this->assertSame(1, PasswordAuditLog::where('event', 'password_changed')->where('user_id', $user->id)->count());
    }

    public function test_unrelated_update_is_not_logged_as_password_change(): void
    {
        $user = $this->user();

        $user->name = 'New Name';
        $user->save();

        $this->assertSame(0, PasswordAuditLog::where('event', 'password_changed')->count());
    }

    public function test_password_reset_is_logged(): void
    {
        $user = $this->user();

        Event::dispatch(new PasswordReset($user));

        $this->assertSame(1, PasswordAuditLog::where('event', 'password_reset_completed')->count());
    }

    public function test_context_is_redacted(): void
    {
        app(AuditLogger::class)->log('custom', 'failure', null, 'x', [
            'password' => 'secret',
            'reset_code' => '123456',
            'note'     => 'fine',
        ]);

        $ctx = PasswordAuditLog::firstOrFail()->context;
        $this->assertSame('[REDACTED]', $ctx['password']);
        $this->assertSame('[REDACTED]', $ctx['reset_code']);
        $this->assertSame('fine', $ctx['note']);
    }

    public function test_logging_can_be_disabled(): void
    {
        config()->set('password-policy.audit.enabled', false);

        Event::dispatch(new Failed('web', null, ['email' => 'a@b.com']));

        $this->assertSame(0, PasswordAuditLog::count());
    }

    public function test_a_failing_audit_write_never_breaks_the_caller(): void
    {
        \Illuminate\Support\Facades\Schema::drop('password_audit_logs');

        $result = app(AuditLogger::class)->log('x', 'success');

        $this->assertNull($result);
    }

    public function test_gate_denies_by_default_and_host_can_override(): void
    {
        $user = $this->user();

        $this->assertTrue(Gate::forUser($user)->denies('view-password-audit-logs'));

        Gate::define('view-password-audit-logs', fn ($u) => $u->email === 't@example.com');

        $this->assertTrue(Gate::forUser($user)->allows('view-password-audit-logs'));
    }

    public function test_monolog_tap_redacts_secrets(): void
    {
        $handler = new TestHandler();
        $logger = new Logger('t', [$handler]);

        (new RedactSensitiveData())($logger);
        $logger->warning('login', ['password' => 'Hunter2!', 'email' => 'a@b.com']);

        $record = $handler->getRecords()[0];
        $this->assertSame('[REDACTED]', $record->context['password']);
        $this->assertSame('a@b.com', $record->context['email']);
    }

    public function test_audit_command_lists_entries(): void
    {
        app(AuditLogger::class)->log('password_changed', 'success', null, 'cli@example.com');

        $this->artisan('password-policy:audit')
            ->expectsOutputToContain('cli@example.com')
            ->assertSuccessful();
    }
}
