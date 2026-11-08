<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api\Admin;

use Illuminate\Http\Request;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Exceptions\DeliveryFailedException;
use Mainul\PasswordPolicy\Exceptions\NoSecureChannelException;
use Mainul\PasswordPolicy\Http\Controllers\Api\ApiController;
use Mainul\PasswordPolicy\Http\Resources\UserSecurityResource;
use Mainul\PasswordPolicy\Services\AccountService;
use Mainul\PasswordPolicy\Services\ExpiredAccountSweeper;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\OffboardingService;
use Mainul\PasswordPolicy\Services\SessionTerminator;
use Mainul\PasswordPolicy\Services\TemporaryPasswordService;
use Mainul\PasswordPolicy\Services\TotpEnrollmentService;

/** Account actions an administrator can take on one user. Every one is audited. */
class UserController extends ApiController
{
    public function show(Request $request, string $user)
    {
        $this->authorizeAbility($request, 'users');

        return new UserSecurityResource($this->findUser($user));
    }

    public function unlock(Request $request, string $user, LockoutService $lockout)
    {
        $this->authorizeAbility($request, 'users');
        $data = $request->validate(['verified_by' => ['nullable', 'string', 'max:255']]);
        $target = $this->findUser($user);

        try {
            $lockout->unlock($target, $data['verified_by'] ?? null);
        } catch (InvalidArgumentException $e) {
            return response()->json([
                'message' => $e->getMessage(),
                'errors'  => ['verified_by' => [$e->getMessage()]],
            ], 422);
        }

        return new UserSecurityResource($target->refresh());
    }

    public function disable(Request $request, string $user, AccountService $accounts)
    {
        $this->authorizeAbility($request, 'users');
        $data = $request->validate(['reason' => ['nullable', 'string', 'max:255']]);
        $target = $this->findUser($user);

        $accounts->disable($target, $data['reason'] ?? 'administrator', $this->actor($request));

        return new UserSecurityResource($target->refresh());
    }

    /** The user must change their password at the next login. */
    public function enable(Request $request, string $user, AccountService $accounts)
    {
        $this->authorizeAbility($request, 'users');
        $target = $this->findUser($user);

        $accounts->enable($target, $this->actor($request));

        return new UserSecurityResource($target->refresh());
    }

    /** Confirmed compromise: password made unusable, every session ended (3.7.5). */
    public function compromise(Request $request, string $user, AccountService $accounts)
    {
        $this->authorizeAbility($request, 'users');
        $target = $this->findUser($user);

        $accounts->markCompromised($target, $this->actor($request));

        return new UserSecurityResource($target->refresh());
    }

    /** New temporary password, sent to the user's approved channel only. */
    public function temporaryPassword(Request $request, string $user, TemporaryPasswordService $service)
    {
        $this->authorizeAbility($request, 'users');
        $target = $this->findUser($user);

        try {
            $channel = $service->issueFor($target);
        } catch (NoSecureChannelException $e) {
            return $this->error('This user has no approved channel (company email or registered phone) to receive a password.', 'no_secure_channel', 422);
        } catch (DeliveryFailedException $e) {
            return $this->error('The password could not be delivered. Nothing was changed.', 'delivery_failed', 502);
        }

        // The password itself is never returned.
        return $this->message('Temporary password sent.', 200, ['channel' => $channel]);
    }

    public function terminateSessions(Request $request, string $user, SessionTerminator $sessions)
    {
        $this->authorizeAbility($request, 'users');
        $target = $this->findUser($user);

        $sessions->terminate($target, false, 'administrator');

        return $this->message('All sessions and tokens ended.');
    }

    /** Leaver: disable, end sessions, mark the shared passwords they knew as due (3.8.3, 3.8.5). */
    public function offboard(Request $request, string $user, OffboardingService $offboarding)
    {
        $this->authorizeAbility($request, 'users');
        $target = $this->findUser($user);

        $exposed = $offboarding->offboard($target, $this->actor($request));

        return response()->json([
            'user'              => (new UserSecurityResource($target->refresh()))->resolve($request),
            'rotation_required' => $exposed->map(fn ($a) => [
                'user_id' => $a->user_id,
                'owner'   => $a->owner,
                'purpose' => $a->purpose,
            ])->values(),
        ]);
    }

    /** Lost device: wipe the authenticator app so the user enrols again. */
    public function resetMfa(Request $request, string $user, TotpEnrollmentService $enrollment)
    {
        $this->authorizeAbility($request, 'users');
        $target = $this->findUser($user);

        $removed = $enrollment->reset($target, $this->actor($request));

        return $this->message($removed ? 'Authenticator app reset.' : 'The user had no authenticator app.');
    }

    /** Disable every account whose expired password went unchanged past the grace period (3.5.1). */
    public function disableExpired(Request $request, ExpiredAccountSweeper $sweeper)
    {
        $this->authorizeAbility($request, 'users');
        $data = $request->validate(['dry_run' => ['sometimes', 'boolean']]);
        $dryRun = (bool) ($data['dry_run'] ?? false);

        $count = $sweeper->sweep($dryRun, (string) $request->user()->getAuthIdentifier());

        if ($count === null) {
            return $this->message('Automatic disabling is turned off.', 200, ['count' => 0, 'enabled' => false]);
        }

        return response()->json(['enabled' => true, 'dry_run' => $dryRun, 'count' => $count]);
    }
}
