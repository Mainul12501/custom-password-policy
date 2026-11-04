<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires HTTPS and keeps passwords out of URLs (Policy 3.3.1, 3.3.2).
 *
 * Active only in production by default (password-policy.tls.enforce = null).
 */
class EnforceSecureTransport
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->isActive()) {
            return $next($request);
        }

        // Checked first so a redirect never echoes a password-bearing URL.
        if ($this->hasPasswordInQuery($request->query())) {
            return response()->json([
                'message' => 'Passwords must never be sent in the URL or query string.',
                'error'   => 'password_in_query_string',
            ], 400);
        }

        if (! $request->isSecure()) {
            if ($request->isMethod('GET') && ! $request->expectsJson()) {
                return redirect()->secure($request->getRequestUri(), 301);
            }

            return response()->json([
                'message' => 'HTTPS is required.',
                'error'   => 'https_required',
            ], 403);
        }

        return $next($request);
    }

    protected function isActive(): bool
    {
        $enforce = config('password-policy.tls.enforce');

        return $enforce === null ? app()->environment('production') : (bool) $enforce;
    }

    protected function hasPasswordInQuery(array $query): bool
    {
        $forbidden = array_map('strtolower', config('password-policy.tls.forbidden_query_keys', []));

        foreach ($query as $key => $value) {
            if (is_string($key) && in_array(strtolower($key), $forbidden, true)) {
                return true;
            }

            if (is_array($value) && $this->hasPasswordInQuery($value)) {
                return true;
            }
        }

        return false;
    }
}
