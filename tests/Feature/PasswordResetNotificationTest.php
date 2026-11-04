<?php

namespace Mainul\PasswordPolicy\Tests\Feature;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Tests\Support\FailingChannel;
use Mainul\PasswordPolicy\Tests\Support\FakeSmsChannel;
use Mainul\PasswordPolicy\Tests\Support\MailInspector;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class PasswordResetNotificationTest extends TestCase
{
    use MailInspector;

    protected function user(array $attrs = []): User
    {
        return User::create(array_merge([
            'name'     => 'T',
            'email'    => 't@example.com',
            'password' => Hash::make('Secret@123'),
        ], $attrs));
    }

    public function test_user_is_emailed_after_a_reset_without_any_password_in_it(): void
    {
        $this->useArrayMailer();
        $user = $this->user();

        Event::dispatch(new PasswordReset($user));

        $bodies = $this->sentTextBodies();
        $this->assertCount(1, $bodies);
        $this->assertStringContainsString('Your password was reset on', $bodies[0]);
        $this->assertStringContainsString('report it to IT Security', $bodies[0]);
        $this->assertStringNotContainsString($user->password, $bodies[0]);

        $to = $this->sentMail()[0]->getOriginalMessage()->getTo()[0]->getAddress();
        $this->assertSame('t@example.com', $to);

        $log = PasswordAuditLog::where('event', 'reset_notification')->firstOrFail();
        $this->assertSame('success', $log->outcome);
        $this->assertSame(['channel' => 'mail'], $log->context);
    }

    public function test_phone_only_user_is_notified_by_sms(): void
    {
        config()->set('password-policy.temporary_password.channels.sms', FakeSmsChannel::class);
        FakeSmsChannel::$texts = [];
        $this->useArrayMailer();

        Event::dispatch(new PasswordReset($this->user(['email' => 'bad', 'phone' => '01700000000'])));

        $this->assertCount(1, FakeSmsChannel::$texts);
        $this->assertStringContainsString('Your password was reset', FakeSmsChannel::$texts[0][1]);
        $this->assertSame([], $this->sentMail());
    }

    public function test_no_channel_is_audited_and_does_not_break_the_reset(): void
    {
        Event::dispatch(new PasswordReset($this->user(['email' => 'bad'])));

        $log = PasswordAuditLog::where('event', 'reset_notification')->firstOrFail();
        $this->assertSame('failure', $log->outcome);
        $this->assertSame(['error' => 'NoSecureChannelException'], $log->context);
    }

    public function test_delivery_failure_is_audited_and_does_not_break_the_reset(): void
    {
        config()->set('password-policy.temporary_password.channels.mail', FailingChannel::class);

        Event::dispatch(new PasswordReset($this->user()));

        $this->assertSame(
            1,
            PasswordAuditLog::where('event', 'reset_notification')->where('outcome', 'failure')->count()
        );
    }

    public function test_notification_can_be_turned_off(): void
    {
        $this->useArrayMailer();
        config()->set('password-policy.reset.notify', false);

        Event::dispatch(new PasswordReset($this->user()));

        $this->assertSame([], $this->sentMail());
    }

    public function test_reset_link_request_is_audited(): void
    {
        $user = $this->user();

        Event::dispatch(new PasswordResetLinkSent($user));

        $log = PasswordAuditLog::where('event', 'password_reset_requested')->firstOrFail();
        $this->assertSame($user->id, $log->user_id);
    }
}
