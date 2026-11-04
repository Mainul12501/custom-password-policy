<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Mainul\PasswordPolicy\Services\SessionTerminator;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rejects sessions created before the user's last session termination
 * (Policy 3.8.4). Works with any session driver.
 *
 * A session with no stored version (created before this middleware was
 * deployed) adopts the current one on first sight.
 */
class EnsureSessionVersion
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user || ! $request->hasSession()) {
            return $next($request);
        }

        $current = (int) ($user->session_version ?? 0);
        $stored = $request->session()->get(SessionTerminator::SESSION_KEY);

        if ($stored === null) {
            $request->session()->put(SessionTerminator::SESSION_KEY, $current);

            return $next($request);
        }

        if ((int) $stored !== $current) {
            $guard = Auth::guard();

            if (method_exists($guard, 'logout')) {
                $guard->logout();
            }

            $request->session()->invalidate();

            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'Your session has ended. Please sign in again.',
                    'error'   => 'session_terminated',
                ], 401);
            }

            abort(401, 'Your session has ended. Please sign in again.');
        }

        return $next($request);
    }
}
