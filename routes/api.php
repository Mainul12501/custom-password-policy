<?php

use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Http\Controllers\Api\AccessController;
use Mainul\PasswordPolicy\Http\Controllers\Api\Admin\AuditController;
use Mainul\PasswordPolicy\Http\Controllers\Api\Admin\ComplianceController;
use Mainul\PasswordPolicy\Http\Controllers\Api\Admin\ServiceAccountController;
use Mainul\PasswordPolicy\Http\Controllers\Api\Admin\SettingsController;
use Mainul\PasswordPolicy\Http\Controllers\Api\Admin\UserController;
use Mainul\PasswordPolicy\Http\Controllers\Api\MfaController;
use Mainul\PasswordPolicy\Http\Controllers\Api\PasswordController;

// Always registered; every route answers 404 until `api.enabled` is true
// (config or the password_policy_settings table).
$publicThrottle = 'throttle:' . config('password-policy.api.throttle.public', '6,1');
$sensitiveThrottle = 'throttle:' . config('password-policy.api.throttle.sensitive', '10,1');

$adminStack = ['password.expiry', 'password.force_change'];
if (config('password-policy.api.admin_requires_mfa', true)) {
    $adminStack[] = 'password.mfa';
}

Route::prefix(config('password-policy.api.prefix', 'api/password-policy'))
    ->middleware(array_merge((array) config('password-policy.api.middleware', ['api']), ['password.api']))
    ->name('password-policy.api.')
    ->group(function () use ($publicThrottle, $sensitiveThrottle, $adminStack) {

        // Not signed in -------------------------------------------------------
        Route::middleware($publicThrottle)->group(function () {
            Route::post('login/check', [AccessController::class, 'loginCheck'])->name('login.check');
            Route::post('reset/code', [AccessController::class, 'requestResetCode'])->name('reset.code');
            Route::post('reset/password', [AccessController::class, 'resetPassword'])->name('reset.password');
        });

        // Signed in -----------------------------------------------------------
        Route::middleware(['password.api_auth', 'password.account_active', 'password.session_version'])
            ->group(function () use ($sensitiveThrottle, $adminStack) {

                // Own password. Reachable with an expired or temporary password.
                Route::get('policy', [PasswordController::class, 'policy'])->name('policy');
                Route::get('password/status', [PasswordController::class, 'status'])->name('password.status');
                Route::post('password/validate', [PasswordController::class, 'validatePassword'])->name('password.validate');
                Route::put('password', [PasswordController::class, 'update'])->middleware($sensitiveThrottle)->name('password.update');

                // Own authenticator app.
                Route::prefix('mfa')->name('mfa.')->group(function () use ($sensitiveThrottle) {
                    Route::get('status', [MfaController::class, 'status'])->name('status');
                    Route::post('enroll', [MfaController::class, 'enroll'])->name('enroll');
                    Route::post('enroll/confirm', [MfaController::class, 'confirmEnrollment'])->middleware($sensitiveThrottle)->name('enroll.confirm');
                    Route::post('verify', [MfaController::class, 'verify'])->middleware($sensitiveThrottle)->name('verify');
                    Route::post('recovery-codes', [MfaController::class, 'regenerateRecoveryCodes'])->middleware($sensitiveThrottle)->name('recovery');
                });

                // Administration. Each action is checked against a Gate ability.
                Route::prefix('admin')->name('admin.')->middleware($adminStack)->group(function () {
                    Route::prefix('users/{user}')->name('users.')->group(function () {
                        Route::get('/', [UserController::class, 'show'])->name('show');
                        Route::post('unlock', [UserController::class, 'unlock'])->name('unlock');
                        Route::post('disable', [UserController::class, 'disable'])->name('disable');
                        Route::post('enable', [UserController::class, 'enable'])->name('enable');
                        Route::post('compromise', [UserController::class, 'compromise'])->name('compromise');
                        Route::post('temporary-password', [UserController::class, 'temporaryPassword'])->name('temporary-password');
                        Route::post('terminate-sessions', [UserController::class, 'terminateSessions'])->name('terminate-sessions');
                        Route::post('offboard', [UserController::class, 'offboard'])->name('offboard');
                        Route::delete('mfa', [UserController::class, 'resetMfa'])->name('mfa.reset');
                    });

                    Route::post('accounts/disable-expired', [UserController::class, 'disableExpired'])->name('accounts.disable-expired');

                    Route::get('service-accounts', [ServiceAccountController::class, 'index'])->name('service-accounts.index');
                    Route::post('service-accounts', [ServiceAccountController::class, 'store'])->name('service-accounts.store');
                    Route::post('service-accounts/rotate-due', [ServiceAccountController::class, 'rotateDue'])->name('service-accounts.rotate-due');
                    Route::post('service-accounts/{user}/rotate', [ServiceAccountController::class, 'rotate'])->name('service-accounts.rotate');

                    Route::get('settings', [SettingsController::class, 'index'])->name('settings.index');
                    Route::put('settings', [SettingsController::class, 'update'])->name('settings.update');
                    Route::delete('settings/{key}', [SettingsController::class, 'destroy'])->where('key', '[a-z_.]+')->name('settings.destroy');

                    Route::get('audit', [AuditController::class, 'index'])->name('audit');

                    Route::get('compliance', [ComplianceController::class, 'check'])->name('compliance');
                    Route::post('compliance/default-passwords', [ComplianceController::class, 'scanDefaults'])->name('compliance.defaults.scan');
                    Route::get('compliance/default-passwords/{scanId}', [ComplianceController::class, 'scanResult'])->name('compliance.defaults.result');
                });
            });
    });
