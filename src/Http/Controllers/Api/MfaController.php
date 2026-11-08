<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Mfa\QrCode;
use Mainul\PasswordPolicy\Services\MfaService;
use Mainul\PasswordPolicy\Services\TotpEnrollmentService;

/**
 * Authenticator-app set-up and verification for API callers. Verification is
 * remembered per access token (see MfaService::markVerified).
 */
class MfaController extends ApiController
{
    public function __construct(
        protected MfaService $mfa,
        protected TotpEnrollmentService $enrollment,
    ) {
    }

    public function status(Request $request)
    {
        $user = $request->user();
        $hasDriver = $this->mfa->hasDriver();
        $enrolled = $hasDriver && $this->mfa->isEnrolled($user);

        return response()->json(['data' => [
            'totp_enabled'             => $this->mfa->totpEnabled(),
            'driver_available'         => $hasDriver,
            'required'                 => $this->mfa->isRequired($user, $request),
            'enrolled'                 => $enrolled,
            'verified'                 => $enrolled && $this->mfa->isVerified($user, $request),
            'in_enrollment_grace'      => $this->mfa->inEnrollmentGrace(),
            'built_in'                 => $this->builtIn(),
            'recovery_codes_remaining' => $this->builtIn() ? $this->enrollment->recoveryCodesRemaining($user) : 0,
        ]]);
    }

    /** Start (or resume) enrolment: returns the key and the otpauth URI. */
    public function enroll(Request $request)
    {
        if ($denied = $this->builtInUnavailable()) {
            return $denied;
        }

        $user = $request->user();

        // An enrolled factor is never replaced from a password-only token.
        if ($this->enrollment->isEnrolled($user)) {
            return $this->error('An authenticator app is already set up. Ask an administrator to reset it.', 'mfa_already_enrolled', 409);
        }

        $setup = $this->enrollment->begin($user);

        return response()->json(['data' => [
            'secret'  => $setup['secret'],
            'uri'     => $setup['uri'],
            'qr_svg'  => QrCode::svg($setup['uri']),
        ]]);
    }

    public function confirmEnrollment(Request $request)
    {
        if ($denied = $this->builtInUnavailable()) {
            return $denied;
        }

        $request->validate(['code' => ['required', 'string', 'max:64']]);
        $user = $request->user();

        if ($this->enrollment->isEnrolled($user)) {
            return $this->error('An authenticator app is already set up.', 'mfa_already_enrolled', 409);
        }

        $codes = $this->enrollment->confirm($user, (string) $request->input('code'));

        if ($codes === null) {
            return $this->invalidCode();
        }

        $this->mfa->markVerified($user, $request);

        // Shown once; they are not stored in readable form.
        return response()->json(['data' => ['recovery_codes' => $codes]]);
    }

    /**
     * Start a challenge for drivers that need one (send an SMS code, push a
     * prompt). The built-in authenticator app has nothing to send.
     */
    public function challenge(Request $request)
    {
        if ($denied = $this->unavailable()) {
            return $denied;
        }

        $user = $request->user();

        if (! $this->mfa->isEnrolled($user)) {
            return $this->error('Multi-factor authentication is not set up for this account.', 'mfa_not_enrolled', 409);
        }

        $this->mfa->challenge($user);

        return $this->message('Challenge started.');
    }

    public function verify(Request $request)
    {
        if ($denied = $this->unavailable()) {
            return $denied;
        }

        $request->validate(['code' => ['required', 'string', 'max:64']]);

        if (! $this->mfa->verify($request->user(), (string) $request->input('code'), $request)) {
            return $this->invalidCode('That code is not correct, or the account is locked.');
        }

        return $this->message('Verified.', 200, ['verified' => true]);
    }

    public function regenerateRecoveryCodes(Request $request)
    {
        if ($denied = $this->builtInUnavailable()) {
            return $denied;
        }

        $user = $request->user();

        if (! $this->mfa->isVerified($user, $request)) {
            return $this->error('Verify your code first.', 'mfa_required', 403);
        }

        $request->validate(['password' => ['required', 'string']]);

        if (! Hash::check((string) $request->input('password'), $user->getAuthPassword())) {
            return response()->json([
                'message' => 'The password is not correct.',
                'errors'  => ['password' => ['The password is not correct.']],
            ], 422);
        }

        return response()->json(['data' => ['recovery_codes' => $this->enrollment->regenerateRecoveryCodes($user)]]);
    }

    /** Any driver: the built-in authenticator app or the host's own. */
    protected function unavailable()
    {
        return $this->mfa->hasDriver()
            ? null
            : $this->error('Multi-factor authentication is not available.', 'mfa_disabled', 404);
    }

    /** The built-in authenticator app is the active factor (not a host driver). */
    protected function builtIn(): bool
    {
        return $this->mfa->totpEnabled() && ! config('password-policy.mfa.driver');
    }

    /** Set-up and recovery codes belong to the built-in app; a host driver does its own. */
    protected function builtInUnavailable()
    {
        if ($this->builtIn()) {
            return null;
        }

        return $this->mfa->hasDriver()
            ? $this->error('Set-up is handled by your own MFA driver, not by this package.', 'mfa_external_driver', 404)
            : $this->error('Authenticator app login is not enabled.', 'mfa_disabled', 404);
    }

    protected function invalidCode(string $message = 'That code is not correct. Check the app and try again.')
    {
        return response()->json(['message' => $message, 'errors' => ['code' => [$message]]], 422);
    }
}
