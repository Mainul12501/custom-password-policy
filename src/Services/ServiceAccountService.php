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

    /**
     * Change owner, purpose, rotation period or the list of people who know
     * the password. Only the keys given are changed.
     *
     * @param  array{owner?:string,purpose?:string,rotation_days?:int,known_by?:array<int,int|string>}  $changes
     */
    public function update(Model $user, array $changes): ServiceAccount
    {
        $account = ServiceAccount::where('user_id', $user->getKey())->first();

        if (! $account) {
            throw new RuntimeException('This user is not a registered service account.');
        }

        $fill = array_intersect_key($changes, array_flip(['owner', 'purpose', 'rotation_days']));

        if (array_key_exists('known_by', $changes)) {
            $fill['known_by'] = array_values(array_map('intval', (array) $changes['known_by']));
        }

        if (isset($fill['rotation_days'])) {
            $last = $account->last_rotated_at ?? $user->password_changed_at ?? null;
            $fill['next_rotation_at'] = ($last ? \Carbon\Carbon::parse($last) : now())->addDays((int) $fill['rotation_days']);
        }

        $account->update($fill);

        $this->audit->log('service_account_updated', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'changed' => array_keys($fill),
        ]);

        return $account->refresh();
    }

    /** Stop treating the user as a service account (it expires like any other from then on). */
    public function remove(Model $user): bool
    {
        $removed = ServiceAccount::where('user_id', $user->getKey())->delete() > 0;

        $this->classifier->forget($user);
        $this->audit->log('service_account_removed', AuditLogger::OUTCOME_SUCCESS, $user);

        return $removed;
    }

    /**
     * Email the owners (when they are addresses) and `notify_recipients` about
     * overdue rotations. Returns how many addresses were told.
     */
    public function notifyDue(?Collection $due = null): int
    {
        $due ??= $this->due();

        if ($due->isEmpty()) {
            return 0;
        }

        $lines = $due->map(fn ($a) => "- account {$a->user_id} (owner {$a->owner}): {$a->purpose}")->implode("\n");
        $recipients = array_filter((array) config('password-policy.service_accounts.notify_recipients', []));

        foreach ($due->pluck('owner') as $owner) {
            if (filter_var($owner, FILTER_VALIDATE_EMAIL)) {
                $recipients[] = $owner;
            }
        }

        $recipients = array_values(array_unique($recipients));

        if ($recipients === []) {
            return 0;
        }

        \Illuminate\Support\Facades\Mail::raw(
            "Service account password rotation is due:\n{$lines}",
            fn ($m) => $m->to($recipients)->subject('Service account rotation due')
        );

        return count($recipients);
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
