<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;
use Mainul\PasswordPolicy\Models\PasswordHistory;

class PasswordHistoryService
{
    public function hasBeenUsed(Authenticatable $user, string $plainPassword): bool
    {
        if (! config('password-policy.history.enabled', true)) {
            return false;
        }

        $maxReuse = app(PolicyProfile::class)->historyCount($user);

        if ($maxReuse <= 0) {
            return false;
        }

        // Check the current password
        if (Hash::check($plainPassword, $user->password)) {
            return true;
        }

        // Check the most recent N-1 history records (current password counts as 1)
        $histories = PasswordHistory::where('user_id', $user->getAuthIdentifier())
            ->orderByDesc('created_at')
            ->limit($maxReuse - 1)
            ->get();

        foreach ($histories as $history) {
            if (Hash::check($plainPassword, $history->password)) {
                return true;
            }
        }

        return false;
    }
}
