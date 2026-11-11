<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Gate;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;
use Mainul\PasswordPolicy\Services\TemporaryPasswordService;

/**
 * Web counterpart of POST api/password-policy/admin/users/{user}/temporary-password.
 * Registered only when `temporary_password.routes` is true. The password is never
 * shown: it goes to the user's approved channel and the admin sees only the channel.
 */
class TemporaryPasswordController extends Controller
{
    public function __invoke(Request $request, string $user, TemporaryPasswordService $service)
    {
        // Same ability as the API's /admin/users endpoints (denied until the host defines it).
        Gate::forUser($request->user())->authorize(config('password-policy.api.abilities.users'));

        $class  = config('password-policy.user_model');
        $target = $class::query()->findOrFail($user);

        try {
            $channel = $service->issueFor($target);
        } catch (NoSecureChannelException) {
            return $this->fail($request, 'This user has no approved channel (company email or registered phone) to receive a password.', 'no_secure_channel', 422);
        } catch (DeliveryFailedException) {
            return $this->fail($request, 'The password could not be delivered. Nothing was changed.', 'delivery_failed', 502);
        }

        $message = 'Temporary password sent.';

        if ($request->expectsJson()) {
            return response()->json(['message' => $message, 'channel' => $channel]);
        }

        return back()->with('status', $message)->with('temporary_password_channel', $channel);
    }

    private function fail(Request $request, string $message, string $code, int $status)
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => $message, 'error' => $code], $status);
        }

        return back()->withErrors(['temporary_password' => $message]);
    }
}
