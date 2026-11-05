<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use LogicException;
use Mainul\PasswordPolicy\Mfa\RecoveryCodes;
use Mainul\PasswordPolicy\Mfa\Totp;
use Mainul\PasswordPolicy\Mfa\TotpDriver;
use Mainul\PasswordPolicy\Models\MfaCredential;

/**
 * Sets up, confirms and resets a user's authenticator app. Build your own UI
 * on this if you do not use the bundled routes.
 */
class TotpEnrollmentService
{
    public function __construct(
        protected Totp $totp,
        protected TotpDriver $driver,
        protected SettingsRepository $settings,
        protected AuditLogger $audit,
        protected LockoutService $lockout,
    ) {
    }

    public function isEnrolled(Authenticatable $user): bool
    {
        return $this->driver->isEnrolled($user);
    }

    /**
     * Start (or resume) enrolment. Returns the Base32 secret and the otpauth
     * URI for the QR code. An already-confirmed app is never replaced here.
     *
     * @return array{secret: string, uri: string}
     */
    public function begin(Authenticatable $user): array
    {
        $credential = $this->driver->credential($user);

        if ($credential?->isConfirmed()) {
            throw new LogicException('An authenticator app is already set up. Ask an administrator to reset it.');
        }

        // Reuse the pending secret so reloading the page keeps the same QR code.
        $credential ??= MfaCredential::create([
            'user_id' => $user->getAuthIdentifier(),
            'secret'  => $this->totp->generateSecret(),
        ]);

        return [
            'secret' => $credential->secret,
            'uri'    => $this->totp->uri($credential->secret, $this->account($user), $this->issuer()),
        ];
    }

    /**
     * Finish enrolment with a code from the app. Returns the one-time recovery
     * codes, or null if the code was wrong.
     *
     * @return string[]|null
     */
    public function confirm(Authenticatable $user, string $code): ?array
    {
        $credential = $this->driver->credential($user);

        if (! $credential || $credential->isConfirmed() || $this->lockout->isLocked($user)) {
            return null;
        }

        if (! $this->driver->verifyCode($credential, $code)) {
            if ($user instanceof Model) {
                $this->lockout->recordFailure($user, request()->ip());
            }
            $this->audit->log('mfa_enroll_failed', AuditLogger::OUTCOME_FAILURE, $user);

            return null;
        }

        $codes = RecoveryCodes::generate((int) config('password-policy.totp.recovery_codes', 8));

        $credential->forceFill([
            'confirmed_at'   => now(),
            'recovery_codes' => $codes['stored'],
        ])->save();

        $this->audit->log('mfa_enrolled', AuditLogger::OUTCOME_SUCCESS, $user);

        return $codes['plain'];
    }

    /**
     * Replace the recovery codes of a confirmed credential.
     *
     * @return string[]
     */
    public function regenerateRecoveryCodes(Authenticatable $user): array
    {
        $credential = $this->driver->credential($user);

        if (! $credential?->isConfirmed()) {
            throw new LogicException('No authenticator app is set up.');
        }

        $codes = RecoveryCodes::generate((int) config('password-policy.totp.recovery_codes', 8));
        $credential->forceFill(['recovery_codes' => $codes['stored']])->save();

        $this->audit->log('mfa_recovery_regenerated', AuditLogger::OUTCOME_SUCCESS, $user);

        return $codes['plain'];
    }

    public function recoveryCodesRemaining(Authenticatable $user): int
    {
        return RecoveryCodes::remaining($this->driver->credential($user)?->recovery_codes);
    }

    /** Administrator reset for a lost device: the user enrols again at next login. */
    public function reset(Authenticatable $user, Authenticatable|string|null $actor = null): bool
    {
        $deleted = MfaCredential::where('user_id', $user->getAuthIdentifier())->delete() > 0;

        $this->audit->log('mfa_reset', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'reset_by' => $actor instanceof Authenticatable ? $actor->getAuthIdentifier() : $actor,
        ]);

        return $deleted;
    }

    public function issuer(): string
    {
        return (string) ($this->settings->get('totp.issuer') ?: config('app.name', 'App'));
    }

    protected function account(Authenticatable $user): string
    {
        $column = config('password-policy.columns.email', 'email');

        return (string) (data_get($user, $column) ?: $user->getAuthIdentifier());
    }
}
