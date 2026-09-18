<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Password Validation Rules
    |--------------------------------------------------------------------------
    |
    | Configure the requirements for password complexity. Each rule can be
    | independently enabled or disabled.
    |
    */
    'rules' => [
        'min_length'        => 8,
        'require_uppercase' => true,
        'require_lowercase' => true,
        'require_numeric'   => true,
        'require_special'   => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Expiry
    |--------------------------------------------------------------------------
    |
    | When enabled, users must change their password after the specified
    | number of days. Set 'enabled' to false or 'days' to 0 to disable.
    |
    */
    'expiry' => [
        'enabled' => true,
        'days'    => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | Password History / Reuse Prevention
    |--------------------------------------------------------------------------
    |
    | When enabled, users cannot reuse their most recent N passwords.
    | max_reuse_count defines how many previous passwords to check against.
    |
    */
    'history' => [
        'enabled'         => true,
        'max_reuse_count' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Configure how the password expiry middleware behaves. Specify the
    | route to redirect web users and routes/paths to exclude from checks.
    |
    */
    'middleware' => [
        'password_change_route' => 'password.change',

        'excluded_routes' => [
            'password.change',
            'password.update',
            'logout',
        ],

        'excluded_paths' => [
            'password/change',
            'logout',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The fully qualified class name of your User model. This is used by
    | the PasswordHistory model for its relationship.
    |
    */
    'user_model' => 'App\\Models\\User',

];
