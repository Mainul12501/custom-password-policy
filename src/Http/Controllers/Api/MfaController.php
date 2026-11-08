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
            'recovery_codes_remaining' => $this->mfa->totpEnabled() ? $this->enrollment->recoveryCodesRemaining($user) : 0,
        ]]);
    }

    /** Start (or resume) enrolment: returns the key and the otpauth URI. */
    public function enroll(Request $request)
    {
        if ($denied = $this->unavailable()) {
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
        if ($denied = $this->unavailable()) {
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
        if ($denied = $this->unavailable()) {
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

    protected function unavailable()
    {
        return $this->mfa->totpEnabled()
            ? null
            : $this->error('Authenticator app login is not enabled.', 'mfa_disabled', 404);
    }

    protected function invalidCode(string $message = 'That code is not correct. Check the app and try again.')
    {
        return response()->json(['message' => $message, 'errors' => ['code' => [$message]]], 422);
    }
}
