<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Mainul\PasswordPolicy\Services\AccountService;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Stops signed-in users whose account has since been disabled or locked, and
 * disables accounts whose expired password went unchanged past the grace
 * period (Policy 3.5.1, 3.4.2, 3.8.3).
 */
class EnsureAccountActive
{
    public function __construct(
        protected AccountService $accounts,
        protected LockoutService $lockout,
        protected PasswordExpiryService $expiry,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user) {
            return $next($request);
        }

        if (! $this->accounts->isDisabled($user) && $this->expiry->isDisableDue($user)) {
            $this->accounts->disable($user, AccountService::REASON_PASSWORD_EXPIRED);
        }

        if ($this->accounts->isDisabled($user)) {
            return $this->deny($request, 'account_disabled', 'Your account has been disabled. Contact the administrator.');
        }

        if ($this->lockout->isLocked($user)) {
            return $this->deny($request, 'account_locked', 'Your account is locked. Try again later or contact the administrator.');
        }

        return $next($request);
    }

    protected function deny(Request $request, string $code, string $message): Response
    {
        $guard = Auth::guard();

        if (method_exists($guard, 'logout')) {
            $guard->logout();
        }

        if ($request->hasSession()) {
            $request->session()->invalidate();
        }

        if ($request->expectsJson()) {
            return response()->json(['message' => $message, 'error' => $code], 403);
        }

        abort(403, $message);
    }
}
