<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Services\SettingsRepository;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates API callers with the guard named by `api.guard` (Sanctum by
 * default, Passport or any other guard by configuration). The guard is read
 * on every request, so changing it in the database takes effect at once.
 */
class ApiAuthenticate
{
    public function __construct(protected SettingsRepository $settings)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        foreach ($this->guards() as $guard) {
            try {
                $authenticated = Auth::guard($guard)->check();
            } catch (InvalidArgumentException) {
                return response()->json([
                    'message' => 'The API authentication guard is not configured correctly.',
                    'error'   => 'api_guard_misconfigured',
                ], 500);
            }

            if ($authenticated) {
                // Makes $request->user() and Auth::user() use this guard.
                Auth::shouldUse($guard);

                return $next($request);
            }
        }

        return response()->json(['message' => 'Unauthenticated.', 'error' => 'unauthenticated'], 401);
    }

    /** @return array<int,string> */
    protected function guards(): array
    {
        $configured = $this->settings->get('api.guard', 'sanctum');
        $list = is_array($configured) ? $configured : explode(',', (string) $configured);

        return array_values(array_filter(array_map('trim', $list), 'strlen'));
    }
}
