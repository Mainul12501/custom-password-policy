<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Services;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Events\UnusualLoginDetected;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Services\AnomalyDetector;
use Mainul\PasswordPolicy\Tests\Support\FakeGeoResolver;
use Mainul\PasswordPolicy\Tests\Support\MailInspector;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

class AnomalyDetectorTest extends TestCase
{
    use MailInspector;

    protected function user(): User
    {
        return User::create([
            'name'     => 'T',
            'email'    => 't@example.com',
            'password' => Hash::make('Secret@123'),
        ]);
    }

    protected function detector(): AnomalyDetector
    {
        return app(AnomalyDetector::class);
    }

    public function test_alert_is_raised_once_when_failures_reach_the_threshold(): void
    {
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        foreach (range(1, 6) as $i) {
            $this->detector()->inspectFailure($user, null, '198.51.100.7');
        }

        Event::assertDispatchedTimes(UnusualLoginDetected::class, 1);
        Event::assertDispatched(UnusualLoginDetected::class, fn ($e) => $e->reasons === ['repeated_failures'] && $e->ip === '198.51.100.7');

        $log = PasswordAuditLog::where('event', 'unusual_login')->firstOrFail();
        $this->assertSame('alert', $log->outcome);
    }

    public function test_two_failures_are_not_unusual(): void
    {
        Event::fake([UnusualLoginDetected::class]);

        $user = $this->user();
        $this->detector()->inspectFailure($user, null, null);
        $this->detector()->inspectFailure($user, null, null);

        Event::assertNotDispatched(UnusualLoginDetected::class);
    }

    public function test_failures_outside_the_window_do_not_add_up(): void
    {
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        $this->detector()->inspectFailure($user, null, null);
        $this->detector()->inspectFailure($user, null, null);
        $this->travel(11)->minutes();
        $this->detector()->inspectFailure($user, null, null);

        Event::assertNotDispatched(UnusualLoginDetected::class);
    }

    public function test_unknown_account_probing_is_detected_by_identifier(): void
    {
        Event::fake([UnusualLoginDetected::class]);

        foreach (range(1, 3) as $i) {
            $this->detector()->inspectFailure(null, 'Ghost@Example.com', '203.0.113.5');
        }

        Event::assertDispatched(UnusualLoginDetected::class, fn ($e) => $e->user === null && $e->identifier === 'Ghost@Example.com');
    }

    public function test_failures_with_neither_user_nor_identifier_are_ignored(): void
    {
        Event::fake([UnusualLoginDetected::class]);

        foreach (range(1, 5) as $i) {
            $this->detector()->inspectFailure(null, null, '203.0.113.5');
        }

        Event::assertNotDispatched(UnusualLoginDetected::class);
    }

    public function test_first_login_only_sets_the_baseline(): void
    {
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        $this->detector()->inspectLogin($user, '198.51.100.7');

        Event::assertNotDispatched(UnusualLoginDetected::class);
        $this->assertSame(1, DB::table('password_known_logins')->count());
    }

    public function test_login_from_the_same_network_is_normal(): void
    {
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        $this->detector()->inspectLogin($user, '198.51.100.7');
        $this->detector()->inspectLogin($user, '198.51.100.200');

        Event::assertNotDispatched(UnusualLoginDetected::class);
        $this->assertSame(1, DB::table('password_known_logins')->count());
    }

    public function test_login_from_a_new_network_raises_an_alert_and_is_remembered(): void
    {
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        $this->detector()->inspectLogin($user, '198.51.100.7');
        $this->detector()->inspectLogin($user, '192.0.2.44');
        $this->detector()->inspectLogin($user, '192.0.2.45');

        Event::assertDispatchedTimes(UnusualLoginDetected::class, 1);
        Event::assertDispatched(UnusualLoginDetected::class, fn ($e) => $e->reasons === ['new_network']);
        $this->assertSame(2, DB::table('password_known_logins')->count(), 'the new network is now known');
    }

    public function test_ip_address_is_never_stored(): void
    {
        $user = $this->user();

        $this->detector()->inspectLogin($user, '198.51.100.7');

        $row = DB::table('password_known_logins')->first();
        $this->assertSame(64, strlen($row->prefix_hash));
        $this->assertStringNotContainsString('198.51', json_encode($row));
    }

    public function test_prefix_hash_groups_by_network(): void
    {
        $d = $this->detector();

        $this->assertSame($d->prefixHash('198.51.100.1'), $d->prefixHash('198.51.100.254'));
        $this->assertNotSame($d->prefixHash('198.51.100.1'), $d->prefixHash('198.51.101.1'));
        $this->assertSame($d->prefixHash('2001:db8:1:1::1'), $d->prefixHash('2001:db8:1:ffff::9'));
        $this->assertNotSame($d->prefixHash('2001:db8:1::1'), $d->prefixHash('2001:db8:2::1'));
        $this->assertNull($d->prefixHash('not-an-ip'));
    }

    public function test_invalid_or_missing_ip_is_ignored(): void
    {
        $user = $this->user();

        $this->detector()->inspectLogin($user, 'garbage');
        $this->detector()->inspectLogin($user, null);

        $this->assertSame(0, DB::table('password_known_logins')->count());
    }

    public function test_country_change_is_reported_when_a_resolver_is_configured(): void
    {
        config()->set('password-policy.anomaly.geo_resolver', FakeGeoResolver::class);
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        $this->detector()->inspectLogin($user, '198.51.100.7');
        $this->detector()->inspectLogin($user, '203.0.113.9');

        Event::assertDispatched(UnusualLoginDetected::class, fn ($e) => $e->reasons === ['new_network', 'new_country']);
    }

    public function test_same_country_on_another_network_is_only_a_new_network(): void
    {
        config()->set('password-policy.anomaly.geo_resolver', FakeGeoResolver::class);
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        $this->detector()->inspectLogin($user, '198.51.100.7');
        $this->detector()->inspectLogin($user, '198.52.1.1');

        Event::assertDispatched(UnusualLoginDetected::class, fn ($e) => $e->reasons === ['new_network']);
    }

    public function test_detection_can_be_turned_off(): void
    {
        config()->set('password-policy.anomaly.enabled', false);
        Event::fake([UnusualLoginDetected::class]);
        $user = $this->user();

        foreach (range(1, 5) as $i) {
            $this->detector()->inspectFailure($user, null, null);
        }
        $this->detector()->inspectLogin($user, '198.51.100.7');
        $this->detector()->inspectLogin($user, '192.0.2.1');

        Event::assertNotDispatched(UnusualLoginDetected::class);
        $this->assertSame(0, DB::table('password_known_logins')->count());
    }

    public function test_laravel_auth_events_feed_the_detector(): void
    {
        Event::fake([UnusualLoginDetected::class]);
        // Fake only our event; the real listeners must still run.
        $user = $this->user();

        for ($i = 0; $i < 3; $i++) {
            Event::dispatch(new Failed('web', $user, ['email' => 't@example.com', 'password' => 'x']));
        }

        Event::assertDispatched(UnusualLoginDetected::class);
    }

    public function test_default_alert_goes_to_the_configured_recipients(): void
    {
        $this->useArrayMailer();
        config()->set('password-policy.anomaly.alert_recipients', ['security@example.com']);
        $user = $this->user();

        foreach (range(1, 3) as $i) {
            $this->detector()->inspectFailure($user, null, '198.51.100.7');
        }

        $bodies = $this->sentTextBodies();
        $this->assertCount(1, $bodies);
        $this->assertStringContainsString('repeated_failures', $bodies[0]);
        $this->assertStringContainsString('198.51.100.7', $bodies[0]);
        $this->assertStringNotContainsString('Secret@123', $bodies[0]);
    }

    public function test_no_recipients_means_no_email(): void
    {
        $this->useArrayMailer();
        $user = $this->user();

        foreach (range(1, 3) as $i) {
            $this->detector()->inspectFailure($user, null, null);
        }

        $this->assertSame([], $this->sentMail());
    }
}
