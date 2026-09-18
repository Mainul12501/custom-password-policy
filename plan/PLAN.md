# Password Policy Package - Plan & Specs

## Overview

`mainul/password-policy` is a Laravel package (supporting Laravel 10-13, PHP 8.2+) that enforces password validation rules, password expiry, and password reuse prevention. It integrates non-invasively with existing Laravel auth packages (Breeze, Jetstream, Laravel UI, Sanctum).

## Architecture

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| Service Provider | `src/PasswordPolicyServiceProvider.php` | Registers config, migrations, middleware, validation rules, event listeners |
| Middleware | `src/Http/Middleware/PasswordExpiryMiddleware.php` | Blocks expired-password users (redirect for web, 403 JSON for API) |
| Validation Rule | `src/Rules/PasswordPolicyRule.php` | Enforces uppercase, lowercase, number, special char, min length |
| Reuse Rule | `src/Rules/PasswordNotReusedRule.php` | Prevents reuse of last N passwords |
| Model | `src/Models/PasswordHistory.php` | Eloquent model for `password_histories` table |
| Trait | `src/Traits/HasPasswordPolicy.php` | Added to User model; hooks into Eloquent events to track password changes |
| Expiry Service | `src/Services/PasswordExpiryService.php` | Checks if `password_changed_at + N days` is past |
| History Service | `src/Services/PasswordHistoryService.php` | Compares plaintext against stored bcrypt hashes |
| Event Listener | `src/Listeners/LogPasswordChange.php` | Safety net for Laravel's PasswordReset event |

### Database Schema

**`password_histories` table:**
- `id` (bigint, PK)
- `user_id` (foreign key to users, cascade delete)
- `password` (string, stores bcrypt hash)
- `created_at`, `updated_at` (timestamps)
- Index on `(user_id, created_at)`

**`users` table modification:**
- Add `password_changed_at` (nullable timestamp) after `password`

### Configuration (`config/password-policy.php`)

| Key | Default | Description |
|-----|---------|-------------|
| `rules.min_length` | 8 | Minimum password length |
| `rules.require_uppercase` | true | Require uppercase letter |
| `rules.require_lowercase` | true | Require lowercase letter |
| `rules.require_numeric` | true | Require digit |
| `rules.require_special` | true | Require special character |
| `expiry.enabled` | true | Enable password expiry |
| `expiry.days` | 90 | Days before expiry |
| `history.enabled` | true | Enable reuse prevention |
| `history.max_reuse_count` | 3 | Number of previous passwords to check |
| `middleware.password_change_route` | `password.change` | Named route for web redirect |
| `middleware.excluded_routes` | `[password.change, password.update, logout]` | Routes to skip |
| `middleware.excluded_paths` | `[password/change, logout]` | URI paths to skip |
| `user_model` | `App\Models\User` | FQCN of User model |

### Middleware Flow

1. Skip if expiry disabled or user unauthenticated
2. Skip if route is in exclusion list
3. Check `password_changed_at + expiry_days` against now
4. If expired: redirect (web) or 403 JSON (API via `expectsJson()`)

### Password History Tracking

- **Primary mechanism:** `HasPasswordPolicy` trait hooks into Eloquent `updating` event
- When `password` field is dirty, stores the OLD hash in `password_histories`, sets `password_changed_at = now()`
- Works universally regardless of which auth package changes the password
- **Reuse check:** `Hash::check()` against current password + last N-1 history records

### Auth Integration

The package is non-invasive. Users must:
1. Add `HasPasswordPolicy` trait to User model
2. Add `password_changed_at` to `$casts` as `datetime`
3. Apply `password.expiry` middleware to route groups
4. Add validation rules to password change controllers
5. Create their own password change route/controller

## File Structure

```
password-policy/
├── composer.json
├── phpunit.xml
├── .gitignore
├── LICENSE
├── config/
│   └── password-policy.php
├── database/
│   └── migrations/
│       ├── 2024_01_01_000001_add_password_changed_at_to_users_table.php
│       └── 2024_01_01_000002_create_password_histories_table.php
├── src/
│   ├── PasswordPolicyServiceProvider.php
│   ├── Http/
│   │   └── Middleware/
│   │       └── PasswordExpiryMiddleware.php
│   ├── Rules/
│   │   ├── PasswordPolicyRule.php
│   │   └── PasswordNotReusedRule.php
│   ├── Models/
│   │   └── PasswordHistory.php
│   ├── Traits/
│   │   └── HasPasswordPolicy.php
│   ├── Services/
│   │   ├── PasswordHistoryService.php
│   │   └── PasswordExpiryService.php
│   └── Listeners/
│       └── LogPasswordChange.php
├── tests/
│   ├── TestCase.php
│   ├── Unit/
│   │   ├── Rules/
│   │   │   ├── PasswordPolicyRuleTest.php
│   │   │   └── PasswordNotReusedRuleTest.php
│   │   └── Services/
│   │       ├── PasswordHistoryServiceTest.php
│   │       └── PasswordExpiryServiceTest.php
│   └── Feature/
│       ├── Middleware/
│       │   └── PasswordExpiryMiddlewareTest.php
│       └── Listeners/
│           └── LogPasswordChangeTest.php
└── plan/
    └── PLAN.md
```

## Verification

1. Run `composer validate` to verify `composer.json`
2. Run `composer install` to install dependencies
3. Run `./vendor/bin/phpunit` to execute all tests
4. Verify all unit and feature tests pass
