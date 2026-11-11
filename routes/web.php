<?php

use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Http\Controllers\Admin\UserActionController;

// Loaded when config('password-policy.admin_routes.enabled') is true.
Route::middleware(config('password-policy.admin_routes.middleware', ['web', 'auth']))
    ->prefix(config('password-policy.admin_routes.prefix', 'admin'))
    ->name('password-policy.admin.')
    ->group(function () {
        Route::prefix('users/{user}')->name('users.')->group(function () {
            Route::post('lock', [UserActionController::class, 'lock'])->name('lock');
            Route::post('unlock', [UserActionController::class, 'unlock'])->name('unlock');
            Route::post('disable', [UserActionController::class, 'disable'])->name('disable');
            Route::post('enable', [UserActionController::class, 'enable'])->name('enable');
            Route::post('compromise', [UserActionController::class, 'compromise'])->name('compromise');
            Route::post('temporary-password', [UserActionController::class, 'temporaryPassword'])->name('temporary-password');
            Route::post('terminate-sessions', [UserActionController::class, 'terminateSessions'])->name('terminate-sessions');
            Route::post('offboard', [UserActionController::class, 'offboard'])->name('offboard');
            Route::delete('mfa', [UserActionController::class, 'resetMfa'])->name('mfa.reset');
        });

        Route::post('accounts/disable-expired', [UserActionController::class, 'disableExpired'])->name('accounts.disable-expired');
    });
