<?php

namespace Mainul\PasswordPolicy\Services;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Exceptions\AccountLockedException;

/**
 * Call from your login action *before* checking credentials, so locked or
 * disabled accounts get no chance to guess a password:
 *
 *     app(LoginGuard::class)->ensureCanAttempt($request->input('email'));
 *
 * Unknown identifiers pass through (the normal failed-login path handles them).
 */
class LoginGuard
{
    public function __construct(
        protected LockoutService $lockout,
        protected AccountService $accounts,
        protected PasswordExpiryService $expiry,
    ) {
    }

    /** @throws AccountLockedException */
    public function ensureCanAttempt(string $identifier): void
    {
        $class = config('password-policy.user_model');
        $column = config('password-policy.columns.email', 'email');

        $user = $class::query()->where($column, $identifier)->first();

        if ($user) {
            $this->ensureUserCanAttempt($user);
        }
    }

    /** @throws AccountLockedException */
    public function ensureUserCanAttempt(Authenticatable $user): void
    {
        if ($this->accounts->isDisabled($user)) {
            throw new AccountLockedException(null, 'disabled');
        }

        if ($this->expiry->isDisableDue($user)) {
            $this->accounts->disable($user, AccountService::REASON_PASSWORD_EXPIRED);

            throw new AccountLockedException(null, 'disabled');
        }

        $state = $this->lockout->lockState($user);

        if ($state) {
            $retry = $state['until'] ? max(0, Carbon::now()->diffInSeconds($state['until'], false)) : null;

            throw new AccountLockedException($retry !== null ? (int) $retry : null, $state['type']);
        }
    }
}
