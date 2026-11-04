<?php

namespace Mainul\PasswordPolicy\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Http\Middleware\Concerns\ChecksExcludedRequests;
use Symfony\Component\HttpFoundation\Response;

/**
 * Blocks every request except the password-change/logout routes while the user
 * still has a temporary password (Policy 3.1.5).
 */
class ForcePasswordChangeMiddleware
{
    use ChecksExcludedRequests;

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user || ! (bool) ($user->must_change_password ?? false)) {
            return $next($request);
        }

        if ($this->isExcluded($request)) {
            return $next($request);
        }

        return $this->blockOrRedirect(
            $request,
            'You must change your temporary password before continuing.',
            'password_change_required'
        );
    }
}
