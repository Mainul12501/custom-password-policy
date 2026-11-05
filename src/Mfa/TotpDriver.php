<?php

namespace Mainul\PasswordPolicy\Mfa;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Contracts\MfaDriver;
use Mainul\PasswordPolicy\Models\MfaCredential;

/**
 * Authenticator-app second factor (Google Authenticator, Microsoft
 * Authenticator, Authy...). Accepts the 6-digit code or a recovery code.
 */
class TotpDriver implements MfaDriver
{
    public function __construct(protected Totp $totp)
    {
    }

    public function credential(Authenticatable $user): ?MfaCredential
    {
        return MfaCredential::where('user_id', $user->getAuthIdentifier())->first();
    }

    public function isEnrolled(Authenticatable $user): bool
    {
        return (bool) $this->credential($user)?->isConfirmed();
    }

    /** Nothing to send: the app generates the code on the phone. */
    public function challenge(Authenticatable $user): void
    {
    }

    public function verify(Authenticatable $user, string $code): bool
    {
        $credential = $this->credential($user);

        if (! $credential || ! $credential->isConfirmed()) {
            return false;
        }

        if ($this->verifyCode($credential, $code)) {
            return true;
        }

        return $this->useRecoveryCode($credential, $code);
    }

    /** Check a TOTP code against a credential (confirmed or not) and block replays. */
    public function verifyCode(MfaCredential $credential, string $code): bool
    {
        $step = $this->totp->verify(
            $credential->secret,
            $code,
            (int) config('password-policy.totp.window', 1),
        );

        if ($step === null) {
            return false;
        }

        // Atomic: only the first request to claim this time-step wins.
        $claimed = MfaCredential::whereKey($credential->getKey())
            ->where(fn ($q) => $q->whereNull('last_used_step')->orWhere('last_used_step', '<', $step))
            ->update(['last_used_step' => $step]);

        return $claimed === 1;
    }

    protected function useRecoveryCode(MfaCredential $credential, string $code): bool
    {
        $updated = RecoveryCodes::consume($credential->recovery_codes ?? [], $code);

        if ($updated === null) {
            return false;
        }

        $credential->forceFill(['recovery_codes' => $updated])->save();

        return true;
    }
}
