<?php

namespace Mainul\PasswordPolicy;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;
use Mainul\PasswordPolicy\Console\AuditCommand;
use Mainul\PasswordPolicy\Console\CheckCommand;
use Mainul\PasswordPolicy\Console\CheckDefaultsCommand;
use Mainul\PasswordPolicy\Console\DisableExpiredAccountsCommand;
use Mainul\PasswordPolicy\Console\OffboardCommand;
use Mainul\PasswordPolicy\Console\RotationDueCommand;
use Mainul\PasswordPolicy\Http\Middleware\RequireMfa;
use Mainul\PasswordPolicy\Events\UnusualLoginDetected;
use Mainul\PasswordPolicy\Http\Middleware\BlockSelfReset;
use Mainul\PasswordPolicy\Http\Middleware\EnforceSecureTransport;
use Mainul\PasswordPolicy\Http\Middleware\EnsureAccountActive;
use Mainul\PasswordPolicy\Http\Middleware\EnsureSessionVersion;
use Mainul\PasswordPolicy\Http\Middleware\ForcePasswordChangeMiddleware;
use Mainul\PasswordPolicy\Http\Middleware\PasswordExpiryMiddleware;
use Mainul\PasswordPolicy\Listeners\AuditAuthenticationEvents;
use Mainul\PasswordPolicy\Listeners\DetectUnusualLogins;
use Mainul\PasswordPolicy\Listeners\LogPasswordChange;
use Mainul\PasswordPolicy\Listeners\NotifyPasswordReset;
use Mainul\PasswordPolicy\Listeners\SendUnusualLoginAlert;
use Mainul\PasswordPolicy\Listeners\TrackLoginFailures;
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
        $this->app->singleton(Services\AuditLogger::class);
        $this->app->singleton(Services\DeliveryResolver::class);
        $this->app->singleton(Services\TemporaryPasswordService::class);
        $this->app->singleton(Services\LockoutService::class);
        $this->app->singleton(Services\SessionTerminator::class);
        $this->app->singleton(Services\AccountService::class);
        $this->app->singleton(Services\AccountClassifier::class);
        $this->app->singleton(Services\PolicyProfile::class);
        $this->app->singleton(Services\MfaService::class);
        $this->app->singleton(Services\ServiceAccountService::class);
        $this->app->singleton(Services\OffboardingService::class);
        $this->app->singleton(Services\ResetEligibility::class);
        $this->app->singleton(Services\AnomalyDetector::class);

        $this->app->bind(
            Contracts\ResetIdentityVerifier::class,
            fn ($app) => $app->make(config('password-policy.reset.verifier', Services\ResetCodeVerifier::class))
        );
    }

    public function boot(): void
    {
        $this->publishAssets();
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->registerMiddleware();
        $this->registerValidationRules();
        $this->registerEventListeners();
        $this->registerAuditGate();
        $this->registerCommands();
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
        $router->aliasMiddleware('password.force_change', ForcePasswordChangeMiddleware::class);
        $router->aliasMiddleware('password.secure', EnforceSecureTransport::class);
        $router->aliasMiddleware('password.account_active', EnsureAccountActive::class);
        $router->aliasMiddleware('password.session_version', EnsureSessionVersion::class);
        $router->aliasMiddleware('password.block_self_reset', BlockSelfReset::class);
        $router->aliasMiddleware('password.mfa', RequireMfa::class);
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

        Event::listen(Login::class, [AuditAuthenticationEvents::class, 'handleLogin']);
        Event::listen(Failed::class, [AuditAuthenticationEvents::class, 'handleFailed']);
        Event::listen(Lockout::class, [AuditAuthenticationEvents::class, 'handleLockout']);
        Event::listen(PasswordReset::class, [AuditAuthenticationEvents::class, 'handlePasswordReset']);

        Event::listen(PasswordReset::class, [NotifyPasswordReset::class, 'handle']);
        // Only emitted by newer Laravel versions; harmless where the class is missing.
        Event::listen('Illuminate\Auth\Events\PasswordResetLinkSent', [AuditAuthenticationEvents::class, 'handleResetLinkSent']);

        Event::listen(Failed::class, [DetectUnusualLogins::class, 'handleFailed']);
        Event::listen(Login::class, [DetectUnusualLogins::class, 'handleLogin']);
        Event::listen(UnusualLoginDetected::class, [SendUnusualLoginAlert::class, 'handle']);

        Event::listen(Failed::class, [TrackLoginFailures::class, 'handleFailed']);
        Event::listen(Login::class, [TrackLoginFailures::class, 'handleLogin']);
    }

    /**
     * Reading password audit logs is denied until the host application defines
     * the ability (Policy 3.7.3). A host Gate::define() runs later and wins.
     */
    protected function registerAuditGate(): void
    {
        $ability = config('password-policy.audit.gate_ability', 'view-password-audit-logs');

        if (! Gate::has($ability)) {
            Gate::define($ability, fn ($user = null) => false);
        }
    }

    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                CheckCommand::class,
                AuditCommand::class,
                DisableExpiredAccountsCommand::class,
                CheckDefaultsCommand::class,
                OffboardCommand::class,
                RotationDueCommand::class,
            ]);
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            if (config('password-policy.expiry.enabled', true) && config('password-policy.expiry.auto_disable', true)) {
                $schedule->command('password-policy:disable-expired')->daily();
            }
        });
    }
}
