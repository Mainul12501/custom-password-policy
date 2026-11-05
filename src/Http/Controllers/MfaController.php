<?php

namespace Mainul\PasswordPolicy\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Mfa\QrCode;
use Mainul\PasswordPolicy\Services\MfaService;
use Mainul\PasswordPolicy\Services\TotpEnrollmentService;

/**
 * Bundled authenticator-app pages. Loaded only when `totp.routes` is true.
 *
 * These routes are exempt from the RequireMfa middleware (they must be
 * reachable before MFA is passed), so each action checks its own state.
 */
class MfaController extends Controller
{
    public function __construct(
        protected MfaService $mfa,
        protected TotpEnrollmentService $enrollment,
    ) {
    }

    public function showEnroll(Request $request)
    {
        $this->ensureAvailable();
        $user = $request->user();

        // An enrolled factor is never replaced from a password-only session.
        if ($this->enrollment->isEnrolled($user)) {
            return redirect()->route('mfa.challenge');
        }

        $setup = $this->enrollment->begin($user);

        return view('password-policy::mfa.enroll', [
            'secret' => $setup['secret'],
            'uri'    => $setup['uri'],
            'qr'     => QrCode::svg($setup['uri']),
        ]);
    }

    public function confirmEnroll(Request $request)
    {
        $this->ensureAvailable();
        $request->validate(['code' => ['required', 'string']]);
        $user = $request->user();

        abort_if($this->enrollment->isEnrolled($user), 403, 'An authenticator app is already set up.');

        $codes = $this->enrollment->confirm($user, $request->string('code'));

        if ($codes === null) {
            return $this->fail($request, 'code', 'That code is not correct. Check the app and try again.');
        }

        $this->mfa->markVerified($user, $request);

        if ($request->expectsJson()) {
            return response()->json(['recovery_codes' => $codes]);
        }

        // Shown once, straight from this response, never stored in the session.
        return view('password-policy::mfa.recovery-codes', ['codes' => $codes]);
    }

    public function showChallenge(Request $request)
    {
        $this->ensureAvailable();
        $user = $request->user();

        if (! $this->enrollment->isEnrolled($user)) {
            return redirect()->route('mfa.enroll');
        }

        if ($this->mfa->isVerified($user, $request)) {
            return redirect()->intended('/');
        }

        $this->mfa->challenge($user);

        return view('password-policy::mfa.challenge');
    }

    public function verify(Request $request)
    {
        $this->ensureAvailable();
        $request->validate(['code' => ['required', 'string', 'max:64']]);

        if (! $this->mfa->verify($request->user(), $request->string('code'), $request)) {
            return $this->fail($request, 'code', 'That code is not correct, or the account is locked.');
        }

        return $request->expectsJson()
            ? response()->json(['message' => 'Verified.'])
            : redirect()->intended('/');
    }

    public function regenerateRecoveryCodes(Request $request)
    {
        $this->ensureAvailable();
        $user = $request->user();

        abort_unless($this->mfa->isVerified($user, $request), 403, 'Verify your code first.');
        $request->validate(['password' => ['required', 'string']]);

        if (! Hash::check($request->string('password'), $user->getAuthPassword())) {
            return $this->fail($request, 'password', 'The password is not correct.');
        }

        $codes = $this->enrollment->regenerateRecoveryCodes($user);

        return $request->expectsJson()
            ? response()->json(['recovery_codes' => $codes])
            : view('password-policy::mfa.recovery-codes', ['codes' => $codes]);
    }

    protected function ensureAvailable(): void
    {
        abort_unless($this->mfa->totpEnabled(), 404);
    }

    protected function fail(Request $request, string $field, string $message)
    {
        if ($request->expectsJson()) {
            return response()->json(['message' => $message, 'errors' => [$field => [$message]]], 422);
        }

        return back()->withErrors([$field => $message]);
    }
}
