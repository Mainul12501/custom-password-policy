<?php

namespace Mainul\PasswordPolicy\Services;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Events\AccountLocked;

/**
 * Tiered, persistent failed-login lockout (Policy 3.4.1, 3.4.2).
 *
 *  - N consecutive failures lock the account for durations[0], durations[1],
 *    durations[2] minutes on successive cycles.
 *  - Later cycles lock for `extended_minutes` and, like a permanent lock,
 *    need an administrator to verify identity before the account is unlocked.
 *  - Several failures from one IP within a short window lock permanently.
 */
class LockoutService
{
    public const LOCK_PERMANENT = 'permanent';
    public const LOCK_VERIFICATION = 'verification';
    public const LOCK_TEMPORARY = 'temporary';

    public function __construct(protected AuditLogger $audit)
    {
    }

    /**
     * Current lock, or null. Failures made while locked do not escalate.
     *
     * @return array{type:string,until:?Carbon}|null
     */
    public function lockState(Authenticatable $user): ?array
    {
        if ((bool) ($user->is_permanently_locked ?? false)) {
            return ['type' => self::LOCK_PERMANENT, 'until' => null];
        }

        $until = $user->locked_until ?? null;
        $until = $until ? Carbon::parse($until) : null;

        if ((bool) ($user->requires_identity_verification ?? false)) {
            return ['type' => self::LOCK_VERIFICATION, 'until' => $until];
        }

        if ($until && $until->isFuture()) {
            return ['type' => self::LOCK_TEMPORARY, 'until' => $until];
        }

        return null;
    }

    public function isLocked(Authenticatable $user): bool
    {
        return $this->lockState($user) !== null;
    }

    /** Call for every failed credential check against an existing user. */
    public function recordFailure(Model&Authenticatable $user, ?string $ip = null): void
    {
        if (! config('password-policy.lockout.enabled', true) || $this->isLocked($user)) {
            return;
        }

        $this->resetStaleCycle($user);

        if ($ip !== null && $this->ipBurstExceeded($user, $ip)) {
            $this->lockPermanently($user, 'ip_burst');

            return;
        }

        $user->newQuery()->whereKey($user->getKey())->increment('failed_login_count');
        $user->forceFill(['last_failed_login_at' => now()])->saveQuietly();
        $user->refresh();

        if ((int) $user->failed_login_count >= (int) config('password-policy.lockout.max_attempts', 5)) {
            $this->startCycle($user);
        }
    }

    /** Call after a successful sign-in. A locked account is left untouched. */
    public function recordSuccess(Model&Authenticatable $user): void
    {
        if ($this->isLocked($user)) {
            return;
        }

        if ((int) ($user->failed_login_count ?? 0) > 0) {
            $user->forceFill(['failed_login_count' => 0])->saveQuietly();
        }
    }

    /**
     * Administrator unlock. Permanent locks and locks that need identity
     * verification require $verifiedBy (who checked the user's identity).
     */
    public function unlock(Model&Authenticatable $user, Authenticatable|string|null $verifiedBy = null): void
    {
        $state = $this->lockState($user);

        if ($state && $state['type'] !== self::LOCK_TEMPORARY && $verifiedBy === null) {
            throw new InvalidArgumentException('Unlocking this account requires the identity of the person who verified the user.');
        }

        $user->forceFill([
            'locked_until'                   => null,
            'is_permanently_locked'          => false,
            'requires_identity_verification' => false,
            'failed_login_count'             => 0,
            'lockout_level'                  => 0,
        ])->saveQuietly();

        $this->audit->log('account_unlocked', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'previous_lock' => $state['type'] ?? null,
            'verified_by'   => $verifiedBy instanceof Authenticatable ? $verifiedBy->getAuthIdentifier() : $verifiedBy,
        ]);
    }

    /**
     * Administrator lock (for example while a suspected takeover is looked
     * into). Permanent: unlocking needs the identity of whoever verified the
     * user, like any other permanent lock.
     */
    public function lock(Model&Authenticatable $user, Authenticatable|string|null $actor = null, string $reason = 'administrator'): void
    {
        $this->lockPermanently($user, $reason);

        $this->audit->log('account_locked_by_admin', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'reason' => $reason,
            'actor'  => $actor instanceof Authenticatable ? $actor->getAuthIdentifier() : $actor,
        ]);
    }

    protected function startCycle(Model&Authenticatable $user): void
    {
        $level = (int) $user->lockout_level + 1;
        $durations = array_values(config('password-policy.lockout.durations', [5, 10, 30]));

        if ($level <= count($durations)) {
            $minutes = (int) $durations[$level - 1];
            $verify = false;
        } else {
            $minutes = (int) config('password-policy.lockout.extended_minutes', 120);
            $verify = true;
        }

        $user->forceFill([
            'lockout_level'                  => $level,
            'failed_login_count'             => 0,
            'locked_until'                   => now()->addMinutes($minutes),
            'requires_identity_verification' => $verify,
        ])->saveQuietly();

        $this->announce($user, $verify ? 'extended' : 'failed_attempts', $level, $minutes);
    }

    protected function lockPermanently(Model&Authenticatable $user, string $reason): void
    {
        $level = (int) $user->lockout_level + 1;

        $user->forceFill([
            'is_permanently_locked'          => true,
            'requires_identity_verification' => true,
            'locked_until'                   => null,
            'failed_login_count'             => 0,
            'lockout_level'                  => $level,
            'last_failed_login_at'           => now(),
        ])->saveQuietly();

        $this->announce($user, $reason, $level, null);
    }

    protected function announce(Authenticatable $user, string $reason, int $level, ?int $minutes): void
    {
        $this->audit->log('account_locked', AuditLogger::OUTCOME_BLOCKED, $user, null, [
            'reason'  => $reason,
            'level'   => $level,
            'minutes' => $minutes,
        ]);

        event(new AccountLocked($user, $reason, $level, $minutes));
    }

    /** No failures for a while: the user starts again at cycle one. */
    protected function resetStaleCycle(Model&Authenticatable $user): void
    {
        $last = $user->last_failed_login_at ?? null;
        $hours = (int) config('password-policy.lockout.reset_after_hours', 24);

        if ($last && Carbon::parse($last)->addHours($hours)->isPast()
            && ((int) $user->lockout_level > 0 || (int) $user->failed_login_count > 0)) {
            $user->forceFill(['lockout_level' => 0, 'failed_login_count' => 0])->saveQuietly();
        }
    }

    protected function ipBurstExceeded(Authenticatable $user, string $ip): bool
    {
        $config = config('password-policy.lockout.ip_burst', []);

        if (! ($config['enabled'] ?? true)) {
            return false;
        }

        $window = (int) ($config['window_seconds'] ?? 60);
        $key = $this->burstKeyPrefix($user) . ':' . sha1($ip);

        Cache::add($key, 0, $window);
        $count = Cache::increment($key);

        return $count >= (int) ($config['attempts'] ?? 5);
    }

    protected function burstKeyPrefix(Authenticatable $user): string
    {
        return 'password-policy:burst:' . $user->getAuthIdentifier();
    }
}
