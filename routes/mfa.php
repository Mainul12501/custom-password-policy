<?php

use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Http\Controllers\MfaController;

// Loaded when config('password-policy.totp.routes') is true.
Route::middleware(config('password-policy.totp.route_middleware', ['web', 'auth']))
    ->prefix('mfa')
    ->group(function () {
        Route::get('enroll', [MfaController::class, 'showEnroll'])->name('mfa.enroll');
        Route::post('enroll', [MfaController::class, 'confirmEnroll'])->name('mfa.enroll.confirm');
        Route::get('challenge', [MfaController::class, 'showChallenge'])->name('mfa.challenge');
        Route::post('challenge', [MfaController::class, 'verify'])->name('mfa.verify');
        Route::post('recovery-codes', [MfaController::class, 'regenerateRecoveryCodes'])->name('mfa.recovery');
    });
