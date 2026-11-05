<?php

namespace Mainul\PasswordPolicy\Tests;

use Mainul\PasswordPolicy\PasswordPolicyServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            PasswordPolicyServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
        ]);

        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('password-policy.user_model', User::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Most tests exercise mechanics, not the shipped defaults, so they run
        // against a lenient baseline. PolicyDefaultsTest covers the defaults.
        config()->set('password-policy.rules.min_length', 8);
        config()->set('password-policy.rules.forbid_personal_info', false);
        config()->set('password-policy.rules.banned_words', []);
        config()->set('password-policy.rules.forbid_patterns', false);
        config()->set('password-policy.expiry.days', 90);
        config()->set('password-policy.history.max_reuse_count', 3);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadLaravelMigrations();
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadMigrationsFrom(__DIR__ . '/migrations');
    }
}
