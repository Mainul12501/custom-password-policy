<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Services\SettingsRepository;
use Symfony\Component\HttpFoundation\Response;

/**
 * First middleware on every API endpoint. Answers 404 while the API is
 * switched off (`api.enabled`, config or database) and makes every response
 * JSON, so errors never turn into redirects or HTML pages.
 */
class ApiGate
{
    public function __construct(protected SettingsRepository $settings)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $request->headers->set('Accept', 'application/json');

        if (! (bool) $this->settings->get('api.enabled', false)) {
            return response()->json(['message' => 'Not found.', 'error' => 'api_disabled'], 404);
        }

        return $next($request);
    }
}
