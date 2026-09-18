<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Symfony\Component\HttpFoundation\Response;

class PasswordExpiryMiddleware
{
    public function __construct(
        protected PasswordExpiryService $expiryService
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('password-policy.expiry.enabled', true)) {
            return $next($request);
        }

        $user = $request->user();

        if (! $user) {
            return $next($request);
        }

        if ($this->isExcluded($request)) {
            return $next($request);
        }

        if ($this->expiryService->isExpired($user)) {
            return $this->respondExpired($request);
        }

        return $next($request);
    }

    protected function isExcluded(Request $request): bool
    {
        $excludedRoutes = config('password-policy.middleware.excluded_routes', []);
        $excludedPaths = config('password-policy.middleware.excluded_paths', []);

        if ($request->route() && in_array($request->route()->getName(), $excludedRoutes)) {
            return true;
        }

        foreach ($excludedPaths as $path) {
            if ($request->is($path) || $request->is("{$path}/*")) {
                return true;
            }
        }

        return false;
    }

    protected function respondExpired(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Your password has expired. Please change your password to continue.',
                'error'   => 'password_expired',
            ], 403);
        }

        $route = config('password-policy.middleware.password_change_route', 'password.change');

        return redirect()->route($route)
            ->with('warning', 'Your password has expired. Please change your password to continue.');
    }
}
