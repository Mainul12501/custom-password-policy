<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Mainul\PasswordPolicy\Models\ServiceAccount;

/**
 * Leaver handling (Policy 3.8.3, 3.8.5): disable the account straight away,
 * end its sessions, and make every shared or service password the leaver
 * knew due for rotation immediately.
 */
class OffboardingService
{
    public function __construct(
        protected AccountService $accounts,
        protected AuditLogger $audit,
    ) {
    }

    /** @return Collection<int,ServiceAccount> accounts whose passwords must now be rotated */
    public function offboard(Model&Authenticatable $user, Authenticatable|string|null $actor = null): Collection
    {
        $this->accounts->disable($user, AccountService::REASON_LEAVER, $actor);

        $exposed = ServiceAccount::whereJsonContains('known_by', (int) $user->getAuthIdentifier())->get();

        foreach ($exposed as $account) {
            $account->update(['next_rotation_at' => now()]);
        }

        $this->audit->log('offboarded', AuditLogger::OUTCOME_SUCCESS, $user, null, [
            'rotation_required' => $exposed->pluck('user_id')->all(),
            'actor'             => $actor instanceof Authenticatable ? $actor->getAuthIdentifier() : $actor,
        ]);

        return $exposed;
    }
}
