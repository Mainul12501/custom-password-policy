<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Services\AuditLogger;
use Mainul\PasswordPolicy\Services\ResetEligibility;
use Symfony\Component\HttpFoundation\Response;

/**
 * Put on the "forgot password" and "reset password" routes. Users with a
 * restricted role (BA, SO...) are told to contact an administrator instead
 * (Policy 3.6.6). Unknown emails pass through so the normal flow answers them.
 */
class BlockSelfReset
{
    public const MESSAGE = 'You cannot reset your own password. Please contact the administrator.';

    public function __construct(
        protected ResetEligibility $eligibility,
        protected AuditLogger $audit,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $field = config('password-policy.columns.email', 'email');
        $email = $request->input($field);

        $user = is_string($email) ? $this->eligibility->findUser($email) : null;

        if ($user === null || $this->eligibility->canSelfReset($user)) {
            return $next($request);
        }

        $this->audit->log('password_reset_requested', AuditLogger::OUTCOME_BLOCKED, $user, null, [
            'reason' => 'restricted_role',
        ]);

        if ($request->expectsJson()) {
            return response()->json(['message' => self::MESSAGE, 'error' => 'self_reset_not_allowed'], 403);
        }

        return back()->withInput($request->only($field))->withErrors([$field => self::MESSAGE]);
    }
}
