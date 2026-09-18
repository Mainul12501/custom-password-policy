<?php

namespace Mainul\PasswordPolicy;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;
use Mainul\PasswordPolicy\Http\Middleware\PasswordExpiryMiddleware;
use Mainul\PasswordPolicy\Listeners\LogPasswordChange;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PasswordHistoryService;

class PasswordPolicyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/password-policy.php',
            'password-policy'
        );

        $this->app->singleton(PasswordHistoryService::class);
        $this->app->singleton(PasswordExpiryService::class);
    }

    public function boot(): void
    {
        $this->publishAssets();
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->registerMiddleware();
        $this->registerValidationRules();
        $this->registerEventListeners();
    }

    protected function publishAssets(): void
    {
        $this->publishes([
            __DIR__ . '/../config/password-policy.php' => config_path('password-policy.php'),
        ], 'password-policy-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations'),
        ], 'password-policy-migrations');
    }

    protected function registerMiddleware(): void
    {
        $router = $this->app->make('router');
        $router->aliasMiddleware('password.expiry', PasswordExpiryMiddleware::class);
    }

    protected function registerValidationRules(): void
    {
        Validator::extend('password_policy', function ($attribute, $value, $parameters, $validator) {
            $rule = new PasswordPolicyRule();

            return $rule->passes($attribute, $value);
        });

        Validator::replacer('password_policy', function ($message, $attribute, $rule, $parameters) {
            if ($message === 'validation.password_policy') {
                return str_replace(':attribute', $attribute, 'The :attribute does not meet the password policy requirements.');
            }

            return $message;
        });
    }

    protected function registerEventListeners(): void
    {
        Event::listen(PasswordReset::class, [LogPasswordChange::class, 'handlePasswordReset']);
    }
}
