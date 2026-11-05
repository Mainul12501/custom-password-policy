<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Services\MfaService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends users who need MFA to enrol or to pass the challenge before anything
 * else (Policy 3.4.3, 3.9.2). Without a configured driver, users who need MFA
 * are blocked: the check fails closed.
 */
class RequireMfa
{
    public function __construct(protected MfaService $mfa)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user || ! $this->mfa->isRequired($user, $request) || $this->isExcluded($request)) {
            return $next($request);
        }

        if (! $this->mfa->hasDriver()) {
            return $this->deny($request, 'mfa_unavailable', 'Multi-factor authentication is required but not available.', null);
        }

        if (! $this->mfa->isEnrolled($user)) {
            if ($this->mfa->inEnrollmentGrace()) {
                return $next($request);
            }

            return $this->deny($request, 'mfa_enrollment_required', 'You must set up multi-factor authentication.', config('password-policy.mfa.enroll_route'));
        }

        if (! $this->mfa->isVerified($user, $request)) {
            return $this->deny($request, 'mfa_required', 'Multi-factor authentication is required.', config('password-policy.mfa.challenge_route'));
        }

        return $next($request);
    }

    protected function isExcluded(Request $request): bool
    {
        if ($request->route() && in_array($request->route()->getName(), (array) config('password-policy.mfa.excluded_routes', []), true)) {
            return true;
        }

        foreach ((array) config('password-policy.mfa.excluded_paths', []) as $path) {
            if ($request->is($path) || $request->is("{$path}/*")) {
                return true;
            }
        }

        return false;
    }

    protected function deny(Request $request, string $code, string $message, ?string $route): Response
    {
        if (! $request->expectsJson() && $route && Route::has($route)) {
            return redirect()->route($route)->with('warning', $message);
        }

        return response()->json(['message' => $message, 'error' => $code], 403);
    }
}
