<?php

namespace Mainul\PasswordPolicy\Http\Middleware\Concerns;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

trait ChecksExcludedRequests
{
    /**
     * Routes/paths that must stay reachable so the user can actually change
     * their password or log out.
     */
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

    protected function blockOrRedirect(Request $request, string $message, string $errorCode): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'message' => $message,
                'error'   => $errorCode,
            ], 403);
        }

        $route = config('password-policy.middleware.password_change_route', 'password.change');

        return redirect()->route($route)->with('warning', $message);
    }
}
