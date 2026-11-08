<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Mainul\PasswordPolicy\Rules\CurrentPasswordRule;
use Mainul\PasswordPolicy\Rules\PasswordNotReusedRule;
use Mainul\PasswordPolicy\Rules\PasswordPolicyRule;
use Mainul\PasswordPolicy\Services\MfaService;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PolicyProfile;

/** What the signed-in user can see and do about their own password. */
class PasswordController extends ApiController
{
    /** The rules that apply to this user (stricter for admins). */
    public function policy(Request $request, PolicyProfile $profile)
    {
        $user = $request->user();
        $rules = $profile->rules($user);

        return response()->json(['data' => [
            'min_length'           => (int) ($rules['min_length'] ?? 11),
            'require_uppercase'    => (bool) ($rules['require_uppercase'] ?? true),
            'require_lowercase'    => (bool) ($rules['require_lowercase'] ?? true),
            'require_numeric'      => (bool) ($rules['require_numeric'] ?? true),
            'require_special'      => (bool) ($rules['require_special'] ?? true),
            'forbid_personal_info' => (bool) ($rules['forbid_personal_info'] ?? false),
            'forbid_patterns'      => (bool) ($rules['forbid_patterns'] ?? false),
            // The word list itself is not disclosed.
            'has_banned_words'     => ! empty($rules['banned_words']),
            'expiry_days'          => $profile->expiryDays($user),
            'history_count'        => config('password-policy.history.enabled', true) ? $profile->historyCount($user) : 0,
        ]]);
    }

    public function status(Request $request, PasswordExpiryService $expiry, PolicyProfile $profile, MfaService $mfa)
    {
        $user = $request->user();
        $changedAt = $user->password_changed_at ?? null;
        $days = $profile->expiryDays($user);
        $expiresAt = $changedAt && $days > 0 ? Carbon::parse($changedAt)->addDays($days) : null;

        $enrolled = $mfa->hasDriver() && $mfa->isEnrolled($user);

        return response()->json(['data' => [
            'password_changed_at'  => $changedAt ? Carbon::parse($changedAt)->toIso8601String() : null,
            'expires_at'           => $expiresAt?->toIso8601String(),
            'days_remaining'       => $expiresAt ? (int) max(0, floor(now()->diffInDays($expiresAt, false))) : null,
            'expired'              => $expiry->isExpired($user),
            'must_change_password' => (bool) ($user->must_change_password ?? false),
            'mfa' => [
                'required' => $mfa->isRequired($user, $request),
                'enrolled' => $enrolled,
                'verified' => $enrolled && $mfa->isVerified($user, $request),
            ],
        ]]);
    }

    /** Check a candidate password without changing anything. */
    public function validatePassword(Request $request)
    {
        $data = $request->validate(['password' => ['required', 'string', 'max:1024']]);
        $user = $request->user();

        $validator = Validator::make($data, [
            'password' => [PasswordPolicyRule::for($user), new PasswordNotReusedRule($user)],
        ]);

        return response()->json([
            'valid'  => ! $validator->fails(),
            'errors' => $validator->errors()->get('password'),
        ]);
    }

    /** Voluntary or forced change (3.5.3, 3.5.4). */
    public function update(Request $request)
    {
        $user = $request->user();

        // A rule object is skipped when the field is missing, so the field must
        // be required explicitly unless the change is forced by the system
        // (temporary password or expired password: the rule accepts "").
        $currentRule = new CurrentPasswordRule($user);
        $needsCurrent = ! $currentRule->passes('current_password', '');

        $request->validate([
            'current_password' => $needsCurrent ? ['required', 'string', $currentRule] : [],
            'password'         => [
                'required', 'string', 'max:1024', 'confirmed',
                PasswordPolicyRule::for($user),
                new PasswordNotReusedRule($user),
            ],
        ]);

        // The trait records history, stamps the date, audits and ends the
        // user's other sessions and tokens (the caller's own token stays).
        $user->forceFill(['password' => Hash::make($request->input('password'))])->save();

        return $this->message('Password changed.');
    }
}
