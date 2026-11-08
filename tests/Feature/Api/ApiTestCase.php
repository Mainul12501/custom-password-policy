<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Api;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Tests\Support\FakeSmsChannel;
use Mainul\PasswordPolicy\Tests\TestCase;
use Mainul\PasswordPolicy\Tests\User;

/** Shared set-up for the API tests: API on, the `web` guard, a recording channel. */
abstract class ApiTestCase extends TestCase
{
    protected const BASE = '/api/password-policy';

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('password-policy.api.enabled', true);
        config()->set('password-policy.api.guard', 'web');
        config()->set('password-policy.temporary_password.channels.mail', FakeSmsChannel::class);
        FakeSmsChannel::$texts = [];
        FakeSmsChannel::$sent = [];
    }

    protected function user(array $attrs = []): User
    {
        static $n = 0;
        $n++;

        return User::create(array_merge([
            'name'     => 'Test User',
            'email'    => "user{$n}@example.com",
            'phone'    => '01700000000',
            'password' => Hash::make('Secret@123'),
            'password_changed_at' => now(),
        ], $attrs));
    }

    /** Signed-in admin who is allowed every API ability. */
    protected function admin(array $attrs = []): User
    {
        foreach (config('password-policy.api.abilities') as $ability) {
            Gate::define($ability, fn () => true);
        }
        Gate::define(config('password-policy.audit.gate_ability'), fn () => true);

        return $this->user($attrs + ['email' => 'boss@example.com']);
    }

    protected function url(string $path): string
    {
        return self::BASE . '/' . ltrim($path, '/');
    }
}
