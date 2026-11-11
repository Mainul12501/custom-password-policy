<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Admin;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Gate;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;
use Mainul\PasswordPolicy\Services\AccountService;
use Mainul\PasswordPolicy\Services\ExpiredAccountSweeper;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\OffboardingService;
use Mainul\PasswordPolicy\Services\SessionTerminator;
use Mainul\PasswordPolicy\Services\TemporaryPasswordService;
use Mainul\PasswordPolicy\Services\TotpEnrollmentService;

/**
 * Web counterpart of the API's /admin/users actions. Registered only when
 * `admin_routes.enabled` is true. Every action is audited by its service and
 * checked against the `api.abilities.users` Gate ability.
 *
 * Browser requests are redirected back with a `status` flash (or validation
 * errors); requests that expect JSON get the same JSON shape as the API.
 */
class UserActionController extends Controller
{
    public function lock(Request $request, string $user, LockoutService $lockout)
    {
        $this->authorizeUsers($request);
        $data = $request->validate(['reason' => ['nullable', 'string', 'max:255']]);

        $lockout->lock($this->findUser($user), $request->user(), $data['reason'] ?? 'administrator');

        return $this->done($request, 'Account locked.');
    }

    public function unlock(Request $request, string $user, LockoutService $lockout)
    {
        $this->authorizeUsers($request);
        $data = $request->validate(['verified_by' => ['nullable', 'string', 'max:255']]);

        try {
            $lockout->unlock($this->findUser($user), $data['verified_by'] ?? null);
        } catch (InvalidArgumentException $e) {
            return $this->fail($request, $e->getMessage(), 'invalid_request', 422, 'verified_by');
        }

        return $this->done($request, 'Account unlocked.');
    }

    public function disable(Request $request, string $user, AccountService $accounts)
    {
        $this->authorizeUsers($request);
        $data = $request->validate(['reason' => ['nullable', 'string', 'max:255']]);

        $accounts->disable($this->findUser($user), $data['reason'] ?? 'administrator', $request->user());

        return $this->done($request, 'Account disabled.');
    }

    /** The user must change their password at the next login. */
    public function enable(Request $request, string $user, AccountService $accounts)
    {
        $this->authorizeUsers($request);

        $accounts->enable($this->findUser($user), $request->user());

        return $this->done($request, 'Account enabled. The user must change their password at next login.');
    }

    /** Confirmed compromise: password made unusable, every session ended (3.7.5). */
    public function compromise(Request $request, string $user, AccountService $accounts)
    {
        $this->authorizeUsers($request);

        $accounts->markCompromised($this->findUser($user), $request->user());

        return $this->done($request, 'Account marked as compromised.');
    }

    /** New temporary password, sent to the user's approved channel only (never shown). */
    public function temporaryPassword(Request $request, string $user, TemporaryPasswordService $service)
    {
        $this->authorizeUsers($request);

        try {
            $channel = $service->issueFor($this->findUser($user));
        } catch (NoSecureChannelException) {
            return $this->fail($request, 'This user has no approved channel (company email or registered phone) to receive a password.', 'no_secure_channel', 422, 'temporary_password');
        } catch (DeliveryFailedException) {
            return $this->fail($request, 'The password could not be delivered. Nothing was changed.', 'delivery_failed', 502, 'temporary_password');
        }

        return $this->done($request, 'Temporary password sent.', ['channel' => $channel]);
    }

    public function terminateSessions(Request $request, string $user, SessionTerminator $sessions)
    {
        $this->authorizeUsers($request);

        $sessions->terminate($this->findUser($user), false, 'administrator');

        return $this->done($request, 'All sessions and tokens ended.');
    }

    /** Leaver: disable, end sessions, mark the shared passwords they knew as due (3.8.3, 3.8.5). */
    public function offboard(Request $request, string $user, OffboardingService $offboarding)
    {
        $this->authorizeUsers($request);

        $exposed = $offboarding->offboard($this->findUser($user), $request->user());

        $rotation = $exposed->map(fn ($a) => [
            'user_id' => $a->user_id,
            'owner'   => $a->owner,
            'purpose' => $a->purpose,
        ])->values();

        return $this->done($request, 'User offboarded.', ['rotation_required' => $rotation], [
            'rotation_required' => $rotation->all(),
        ]);
    }

    /** Lost device: wipe the authenticator app so the user enrols again. */
    public function resetMfa(Request $request, string $user, TotpEnrollmentService $enrollment)
    {
        $this->authorizeUsers($request);

        $removed = $enrollment->reset($this->findUser($user), $request->user());

        return $this->done($request, $removed ? 'Authenticator app reset.' : 'The user had no authenticator app.');
    }

    /** Disable every account whose expired password went unchanged past the grace period (3.5.1). */
    public function disableExpired(Request $request, ExpiredAccountSweeper $sweeper)
    {
        $this->authorizeUsers($request);
        $data = $request->validate(['dry_run' => ['sometimes', 'boolean']]);
        $dryRun = (bool) ($data['dry_run'] ?? false);

        $count = $sweeper->sweep($dryRun, (string) $request->user()->getAuthIdentifier());

        if ($count === null) {
            return $this->done($request, 'Automatic disabling is turned off.', ['count' => 0, 'enabled' => false]);
        }

        $verb = $dryRun ? 'would be disabled' : 'disabled';

        return $this->done($request, "{$count} expired account(s) {$verb}.", ['enabled' => true, 'dry_run' => $dryRun, 'count' => $count]);
    }

    // ---------------------------------------------------------------------

    protected function authorizeUsers(Request $request): void
    {
        Gate::forUser($request->user())->authorize(config('password-policy.api.abilities.users'));
    }

    /** @return Model&Authenticatable */
    protected function findUser(string|int $id): Model
    {
        $class = config('password-policy.user_model');

        return $class::query()->findOrFail($id);
    }

    /**
     * @param array $extra     merged into the JSON body and flashed for browsers
     * @param array $flashOnly extra flash data for browsers only (defaults to $extra)
     */
    protected function done(Request $request, string $message, array $extra = [], ?array $flashOnly = null)
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => $message] + $extra);
        }

        $redirect = back()->with('status', $message);

        foreach ($flashOnly ?? $extra as $key => $value) {
            $redirect->with('password_policy.' . $key, $value);
        }

        return $redirect;
    }

    protected function fail(Request $request, string $message, string $code, int $status, string $field)
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => $message, 'error' => $code], $status);
        }

        return back()->withErrors([$field => $message]);
    }
}
