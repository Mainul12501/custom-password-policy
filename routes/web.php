<?php

use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Http\Controllers\Admin\TemporaryPasswordController;

// Loaded when config('password-policy.temporary_password.routes') is true.
Route::middleware(config('password-policy.temporary_password.route_middleware', ['web', 'auth']))
    ->prefix(config('password-policy.temporary_password.route_prefix', 'admin'))
    ->group(function () {
        Route::post('users/{user}/temporary-password', TemporaryPasswordController::class)
            ->name('password-policy.users.temporary-password');
    });
