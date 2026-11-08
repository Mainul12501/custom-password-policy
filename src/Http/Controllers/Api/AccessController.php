<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Mainul\PasswordPolicy\Contracts\ResetIdentityVerifier;
use Mainul\PasswordPolicy\Exceptions\AccountLockedException;
use Mainul\PasswordPolicy\Rules\PasswordNotReusedRule;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Services\AccountService;
use Mainul\PasswordPolicy\Services\LoginGuard;
use Mainul\PasswordPolicy\Services\ResetEligibility;
use Throwable;

/**
 * Endpoints for callers who are not signed in: the pre-login lock check and
 * the one-time-code password reset (3.4.2, 3.6.2, 3.6.6). Answers never reveal
 * whether an account exists.
 */
class AccessController extends ApiController
{
    private const RESET_REQUESTED = 'If the account exists and may reset its own password, a code has been sent.';
    private const RESET_INVALID = 'The code is invalid or has expired, or this account cannot reset its password here.';

    /** Call before checking credentials, so a locked account gets no guesses. */
    public function loginCheck(Request $request, LoginGuard $guard)
    {
        $data = $request->validate(['email' => ['required', 'string', 'max:255']]);

        try {
            $guard->ensureCanAttempt($data['email']);
        } catch (AccountLockedException $e) {
            return response()
                ->json(['message' => $e->getMessage(), 'error' => 'account_unavailable', 'retry_after' => $e->retryAfterSeconds], 423)
                ->withHeaders($e->retryAfterSeconds ? ['Retry-After' => $e->retryAfterSeconds] : []);
        }

        return response()->json(['allowed' => true]);
    }

    /** Send a one-time reset code to the user's approved channel. */
    public function requestResetCode(Request $request, ResetEligibility $eligibility, ResetIdentityVerifier $verifier, AccountService $accounts)
    {
        $data = $request->validate(['email' => ['required', 'string', 'max:255']]);
        $user = $eligibility->findUser($data['email']);

        if ($user && $eligibility->canSelfReset($user) && ! $accounts->isDisabled($user)) {
            try {
                $verifier->issue($user);
            } catch (Throwable $e) {
                // No approved channel or delivery failed: audited by the verifier.
                report($e);
            }
        }

        // Same answer for unknown, restricted, disabled and delivered.
        return response()->json(['message' => self::RESET_REQUESTED], 202);
    }

    /** Check the code, then set the new password. */
    public function resetPassword(
        Request $request,
        ResetEligibility $eligibility,
        ResetIdentityVerifier $verifier,
        AccountService $accounts,
    ) {
        $data = $request->validate([
            'email'    => ['required', 'string', 'max:255'],
            'code'     => ['required', 'string', 'max:64'],
            'password' => ['required', 'string', 'max:1024', 'confirmed', PasswordPolicyRule::for(null)],
        ]);

        $user = $eligibility->findUser($data['email']);

        if (! $user || ! $eligibility->canSelfReset($user) || $accounts->isDisabled($user)
            || ! $verifier->verify($user, $data['code'])) {
            return $this->error(self::RESET_INVALID, 'reset_invalid', 422);
        }

        // The code is spent. Rules that need the user run now, after the
        // identity check, so they cannot be used to probe accounts.
        $validator = Validator::make($data, [
            'password' => [PasswordPolicyRule::for($user), new PasswordNotReusedRule($user)],
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'The password was not accepted. Request a new code to try again.',
                'errors'  => $validator->errors()->toArray(),
                'error'   => 'password_rejected',
            ], 422);
        }

        $user->forceFill(['password' => Hash::make($data['password'])])->save();

        // Same event the Laravel broker fires: audit entry and user notice (3.6.5).
        event(new PasswordReset($user));

        return $this->message('Password reset.');
    }
}
