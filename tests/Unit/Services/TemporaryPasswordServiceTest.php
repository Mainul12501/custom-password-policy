<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;
use Mainul\PasswordPolicy\Mail\TemporaryPasswordMail;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Services\TemporaryPasswordService;
use Mainul\PasswordPolicy\Tests\Support\FailingChannel;
use Mainul\PasswordPolicy\Tests\Support\FakeSmsChannel;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class TemporaryPasswordServiceTest extends TestCase
{
    protected function service(): TemporaryPasswordService
    {
        return app(TemporaryPasswordService::class);
    }

    protected function makeUser(array $attrs = []): User
    {
        return User::create(array_merge([
            'name'     => 'Test User',
            'email'    => 'test.user@example.com',
            'password' => Hash::make('OldPass@123'),
        ], $attrs));
    }

    public function test_generated_password_meets_policy_and_is_unique(): void
    {
        $rule = new PasswordPolicyRule();
        $seen = [];

        for ($i = 0; $i < 50; $i++) {
            $pw = $this->service()->generate();
            $this->assertGreaterThanOrEqual(12, strlen($pw));
            $this->assertTrue($rule->passes('password', $pw), $pw);
            $this->assertDoesNotMatchRegularExpression('/(.)\1\1/', $pw);
            $seen[$pw] = true;
        }

        $this->assertCount(50, $seen);
    }

    public function test_generated_password_never_contains_user_identity(): void
    {
        $user = $this->makeUser(['name' => 'Kamal', 'email' => 'qq9@example.com']);

        for ($i = 0; $i < 30; $i++) {
            $pw = strtolower($this->service()->generate(12, $user));
            $this->assertStringNotContainsString('kamal', $pw);
        }
    }

    public function test_issue_sends_email_sets_hash_and_forces_change(): void
    {
        Mail::fake();
        $user = $this->makeUser();

        $channel = $this->service()->issueFor($user);

        $this->assertSame('mail', $channel);

        $sentMail = null;
        Mail::assertSent(TemporaryPasswordMail::class, function ($mail) use (&$sentMail) {
            $sentMail = $mail;

            return $mail->hasTo('test.user@example.com');
        });

        preg_match('/<strong>(.*?)<\/strong>/', html_entity_decode($sentMail->render()), $m);
        $fresh = $user->fresh();

        $this->assertTrue(Hash::check($m[1], $fresh->password));
        $this->assertNotSame($m[1], $fresh->password, 'stored value must be a hash');
        $this->assertTrue($fresh->mustChangePassword());
    }

    public function test_falls_back_to_sms_only_when_no_company_email(): void
    {
        config()->set('password-policy.temporary_password.channels.sms', FakeSmsChannel::class);
        FakeSmsChannel::$sent = [];
        Mail::fake();

        $user = $this->makeUser(['email' => 'not-an-email', 'phone' => '01700000000']);

        $this->assertSame('sms', $this->service()->issueFor($user));
        $this->assertCount(1, FakeSmsChannel::$sent);
        $this->assertSame('01700000000', FakeSmsChannel::$sent[0][0]);
        Mail::assertNothingSent();
    }

    public function test_email_is_preferred_over_phone(): void
    {
        config()->set('password-policy.temporary_password.channels.sms', FakeSmsChannel::class);
        FakeSmsChannel::$sent = [];
        Mail::fake();

        $user = $this->makeUser(['phone' => '01700000000']);

        $this->assertSame('mail', $this->service()->issueFor($user));
        $this->assertSame([], FakeSmsChannel::$sent);
    }

    public function test_company_email_domain_restriction(): void
    {
        config()->set('password-policy.temporary_password.company_email_domains', ['remarkhb.com']);
        config()->set('password-policy.temporary_password.channels.sms', FakeSmsChannel::class);
        FakeSmsChannel::$sent = [];
        Mail::fake();

        $user = $this->makeUser(['email' => 'someone@gmail.com', 'phone' => '01800000000']);

        $this->assertSame('sms', $this->service()->issueFor($user));
    }

    public function test_no_channel_throws_and_changes_nothing(): void
    {
        $user = $this->makeUser(['email' => 'bad']);
        $before = $user->fresh()->password;

        try {
            $this->service()->issueFor($user);
            $this->fail('Expected NoSecureChannelException');
        } catch (NoSecureChannelException) {
            $this->assertSame($before, $user->fresh()->password);
            $this->assertFalse($user->fresh()->mustChangePassword());
        }
    }

    public function test_failed_delivery_rolls_back_password_change(): void
    {
        config()->set('password-policy.temporary_password.channels.mail', FailingChannel::class);
        $user = $this->makeUser();
        $before = $user->fresh()->password;

        try {
            $this->service()->issueFor($user);
            $this->fail('Expected DeliveryFailedException');
        } catch (DeliveryFailedException) {
            $this->assertSame($before, $user->fresh()->password);
        }

        $this->assertSame(
            1,
            PasswordAuditLog::where('event', 'temp_password_issued')->where('outcome', 'failure')->count()
        );
    }

    public function test_audit_entry_never_contains_the_password(): void
    {
        Mail::fake();
        $user = $this->makeUser();

        $this->service()->issueFor($user);

        $log = PasswordAuditLog::where('event', 'temp_password_issued')->firstOrFail();
        $this->assertSame('success', $log->outcome);
        $this->assertSame(['channel' => 'mail'], $log->context);
    }

    public function test_temporary_password_stays_flagged_when_reissued(): void
    {
        Mail::fake();
        $user = $this->makeUser();

        $this->service()->issueFor($user);
        $this->service()->issueFor($user->fresh());

        $this->assertTrue($user->fresh()->mustChangePassword());
    }

    public function test_real_password_change_clears_forced_change_and_temp_goes_to_history(): void
    {
        Mail::fake();
        $user = $this->makeUser();
        $this->service()->issueFor($user);

        $user = $user->fresh();
        $user->password = Hash::make('Brand@New123');
        $user->save();

        $fresh = $user->fresh();
        $this->assertFalse($fresh->mustChangePassword());
        $this->assertGreaterThanOrEqual(1, $fresh->passwordHistories()->count());
    }
}
