<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use RuntimeException;

/**
 * Registers service accounts and rotates their passwords (Policy 3.9.3, 3.9.4).
 * The new secret goes straight to the vault callback and is never stored,
 * returned or logged here.
 */
class ServiceAccountService
{
    public function __construct(
        protected TemporaryPasswordService $generator,
        protected AccountClassifier $classifier,
        protected AuditLogger $audit,
    ) {
    }

    /**
     * @param  array<int,int|string>  $knownBy  ids of people who know the password
     */
    public function register(
        Model $user,
        string $owner,
        string $purpose,
        ?int $rotationDays = null,
        array $knownBy = [],
    ): ServiceAccount {
        $days = $rotationDays ?? (int) config('password-policy.service_accounts.default_rotation_days', 90);
        $last = $user->password_changed_at ?? null;

        $account = ServiceAccount::updateOrCreate(['user_id' => $user->getKey()], [
            'owner'            => $owner,
            'purpose'          => $purpose,
            'rotation_days'    => $days,
            'last_rotated_at'  => $last,
            'next_rotation_at' => ($last ? \Carbon\Carbon::parse($last) : now())->addDays($days),
            'known_by'         => array_values(array_map('intval', $knownBy)),
        ]);

        $this->classifier->forget($user);
        $this->audit->log('service_account_registered', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'owner' => $owner,
        ]);

        return $account;
    }

    /** @return Collection<int,ServiceAccount> */
    public function due(): Collection
    {
        return ServiceAccount::due()->orderBy('next_rotation_at')->get();
    }

    /**
     * Give the account a new random password and hand it to the vault.
     * If the vault fails the change is rolled back, so the vault and the
     * account never disagree.
     */
    public function rotate(Model $user): void
    {
        $account = ServiceAccount::where('user_id', $user->getKey())->first();

        if (! $account) {
            throw new RuntimeException('This user is not a registered service account.');
        }

        $vault = config('password-policy.service_accounts.vault');

        if (! $vault) {
            throw new RuntimeException('No vault configured (password-policy.service_accounts.vault); refusing to rotate without a place to keep the secret.');
        }

        DB::transaction(function () use ($user, $account, $vault) {
            $secret = $this->generator->generate(
                (int) config('password-policy.service_accounts.password_length', 32),
                $user
            );

            $user->password = Hash::make($secret);
            $user->save();

            app($vault)($user, $secret);

            $account->update([
                'last_rotated_at'  => now(),
                'next_rotation_at' => now()->addDays((int) $account->rotation_days),
            ]);
        });

        $this->audit->log('service_account_rotated', AuditLogger::OUTCOME_SUCCESS, $user);
    }
}
