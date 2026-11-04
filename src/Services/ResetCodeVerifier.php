<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Contracts\ResetIdentityVerifier;
use Throwable;

/**
 * One-time reset codes delivered through the user's approved channel
 * (company email, or registered phone by SMS). Codes are stored hashed, work
 * once, expire after a few minutes and lock after too many wrong guesses
 * (Policy 3.6.2, 3.6.3).
 */
class ResetCodeVerifier implements ResetIdentityVerifier
{
    protected const TABLE = 'password_reset_codes';

    public function __construct(
        protected DeliveryResolver $resolver,
        protected AuditLogger $audit,
    ) {
    }

    public function issue(Authenticatable $user): string
    {
        $channel = $this->resolver->resolve($user);
        $length = max(4, (int) config('password-policy.reset.code_length', 6));
        $ttl = (int) config('password-policy.reset.code_ttl_minutes', 10);

        $code = str_pad((string) random_int(0, (10 ** $length) - 1), $length, '0', STR_PAD_LEFT);

        // Only the newest code is valid.
        DB::table(self::TABLE)->where('user_id', $user->getAuthIdentifier())->whereNull('used_at')->delete();

        $id = DB::table(self::TABLE)->insertGetId([
            'user_id'    => $user->getAuthIdentifier(),
            'code_hash'  => Hash::make($code),
            'expires_at' => now()->addMinutes($ttl),
            'created_at' => now(),
        ]);

        try {
            $channel->sendText(
                $user,
                "Your password reset code is {$code}. It expires in {$ttl} minutes and works once. Do not share it.",
                'Password reset code'
            );
        } catch (Throwable $e) {
            DB::table(self::TABLE)->where('id', $id)->delete();
            $this->audit->log('reset_code_issued', AuditLogger::OUTCOME_FAILURE, $user, null, ['channel' => $channel->name()]);

            throw $e;
        }

        $this->audit->log('reset_code_issued', AuditLogger::OUTCOME_SUCCESS, $user, null, ['channel' => $channel->name()]);

        return $channel->name();
    }

    public function verify(Authenticatable $user, string $code): bool
    {
        $row = DB::table(self::TABLE)
            ->where('user_id', $user->getAuthIdentifier())
            ->whereNull('used_at')
            ->where('expires_at', '>', now())
            ->orderByDesc('id')
            ->first();

        if (! $row || (int) $row->attempts >= (int) config('password-policy.reset.code_max_attempts', 5)) {
            return $this->result($user, false, $row ? 'too_many_attempts' : 'no_active_code');
        }

        if (! Hash::check($code, $row->code_hash)) {
            DB::table(self::TABLE)->where('id', $row->id)->increment('attempts');

            return $this->result($user, false, 'wrong_code');
        }

        // Single use: only the request that flips used_at wins.
        $claimed = DB::table(self::TABLE)->where('id', $row->id)->whereNull('used_at')->update(['used_at' => now()]);

        return $this->result($user, $claimed === 1, $claimed === 1 ? null : 'already_used');
    }

    protected function result(Authenticatable $user, bool $ok, ?string $reason): bool
    {
        $this->audit->log(
            'reset_code_verified',
            $ok ? AuditLogger::OUTCOME_SUCCESS : AuditLogger::OUTCOME_FAILURE,
            $user,
            null,
            $reason ? ['reason' => $reason] : []
        );

        return $ok;
    }
}
