<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Http\Middleware\Concerns\ChecksExcludedRequests;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Symfony\Component\HttpFoundation\Response;

class PasswordExpiryMiddleware
{
    use ChecksExcludedRequests;

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

    protected function respondExpired(Request $request): Response
    {
        return $this->blockOrRedirect(
            $request,
            'Your password has expired. Please change your password to continue.',
            'password_expired'
        );
    }
}
