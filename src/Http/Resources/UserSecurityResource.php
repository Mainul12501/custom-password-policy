<?php

namespace Mainul\PasswordPolicy\Http\Resources;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Mainul\PasswordPolicy\Services\AccountClassifier;
use Mainul\PasswordPolicy\Services\AccountService;
use Mainul\PasswordPolicy\Services\LockoutService;
use Mainul\PasswordPolicy\Services\MfaService;
use Mainul\PasswordPolicy\Services\PasswordExpiryService;
use Mainul\PasswordPolicy\Services\PolicyProfile;

/**
 * The security state of one account. Never contains a password, a hash, an
 * MFA secret or a recovery code.
 */
class UserSecurityResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        $user = $this->resource;
        $classifier = app(AccountClassifier::class);
        $lock = app(LockoutService::class)->lockState($user);
        $mfa = app(MfaService::class);

        $changedAt = $user->password_changed_at ?? null;
        $expiryDays = app(PolicyProfile::class)->expiryDays($user);

        return [
            'id'      => $user->getAuthIdentifier(),
            'email'   => data_get($user, config('password-policy.columns.email', 'email')),
            'name'    => data_get($user, config('password-policy.columns.name', 'name')),

            'is_admin'           => $classifier->isAdmin($user),
            'is_service_account' => $classifier->isServiceAccount($user),

            'disabled'        => app(AccountService::class)->isDisabled($user),
            'disabled_at'     => $this->iso($user->disabled_at ?? null),
            'disabled_reason' => $user->disabled_reason ?? null,

            'locked'      => $lock !== null,
            'lock_type'   => $lock['type'] ?? null,
            'locked_until' => $this->iso($lock['until'] ?? null),
            'failed_login_count' => (int) ($user->failed_login_count ?? 0),

            'password_changed_at' => $this->iso($changedAt),
            'password_expired'    => app(PasswordExpiryService::class)->isExpired($user),
            'password_expires_at' => $changedAt && $expiryDays > 0
                ? Carbon::parse($changedAt)->addDays($expiryDays)->toIso8601String()
                : null,
            'must_change_password' => (bool) ($user->must_change_password ?? false),

            'mfa_required' => $mfa->isRequired($user, $request),
            'mfa_enrolled' => $mfa->hasDriver() ? $mfa->isEnrolled($user) : false,
        ];
    }

    protected function iso(mixed $value): ?string
    {
        return $value ? Carbon::parse($value)->toIso8601String() : null;
    }
}
