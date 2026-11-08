<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * Ends every session and API token of an account (Policy 3.5.2, 3.8.4).
 *
 * Works for any session driver: bumping `session_version` makes the
 * EnsureSessionVersion middleware reject all older sessions. When the session
 * driver is "database" the rows are also deleted, and Sanctum/Passport tokens
 * are removed.
 */
class SessionTerminator
{
    public const SESSION_KEY = 'password_policy.session_version';

    public function __construct(protected AuditLogger $audit)
    {
    }

    /**
     * @param  bool  $keepCurrent  keep the session making this request signed in
     *                             (used when users change their own password)
     */
    public function terminate(Model&Authenticatable $user, bool $keepCurrent = false, string $reason = 'manual'): void
    {
        $query = $user->newQuery()->whereKey($user->getKey());
        $query->increment('session_version');

        $version = (int) $user->newQuery()->whereKey($user->getKey())->value('session_version');
        $user->setAttribute('session_version', $version);
        $user->syncOriginalAttribute('session_version');

        if (array_key_exists('remember_token', $user->getAttributes())) {
            $token = Str::random(60);
            $user->newQuery()->whereKey($user->getKey())->update(['remember_token' => $token]);
            $user->setAttribute('remember_token', $token);
            $user->syncOriginalAttribute('remember_token');
        }

        $currentSessionId = null;
        if ($keepCurrent && $this->isCurrentUser($user)) {
            $session = request()->session();
            $session->put(self::SESSION_KEY, $version);
            $currentSessionId = $session->getId();
        }

        $this->deleteDatabaseSessions($user, $currentSessionId);
        $this->revokeTokens($user, $keepCurrent ? $this->currentTokenId($user) : null);

        $this->audit->log('sessions_terminated', AuditLogger::OUTCOME_SUCCESS, $user, null, ['reason' => $reason]);
    }

    protected function isCurrentUser(Authenticatable $user): bool
    {
        if (! app()->bound('request') || ! request()->hasSession()) {
            return false;
        }

        try {
            return auth()->check() && (string) auth()->id() === (string) $user->getAuthIdentifier();
        } catch (Throwable) {
            return false;
        }
    }

    protected function deleteDatabaseSessions(Authenticatable $user, ?string $exceptId): void
    {
        if (config('session.driver') !== 'database') {
            return;
        }

        try {
            DB::connection(config('session.connection'))
                ->table(config('session.table', 'sessions'))
                ->where('user_id', $user->getAuthIdentifier())
                ->when($exceptId, fn ($q) => $q->where('id', '!=', $exceptId))
                ->delete();
        } catch (Throwable $e) {
            // The version bump already invalidates these sessions.
            report($e);
        }
    }

    protected function revokeTokens(Authenticatable $user, string|int|null $exceptId = null): void
    {
        if (! method_exists($user, 'tokens')) {
            return;
        }

        $user->tokens()
            ->when($exceptId !== null, fn ($q) => $q->where('id', '!=', $exceptId))
            ->delete();
    }

    /**
     * Id of the API token making this request, when it belongs to $user
     * (Sanctum: currentAccessToken(), Passport: token()).
     */
    protected function currentTokenId(Authenticatable $user): string|int|null
    {
        if (! app()->bound('request')) {
            return null;
        }

        try {
            $current = request()->user();

            if (! $current || (string) $current->getAuthIdentifier() !== (string) $user->getAuthIdentifier()) {
                return null;
            }

            $token = method_exists($current, 'currentAccessToken')
                ? $current->currentAccessToken()
                : (method_exists($current, 'token') ? $current->token() : null);

            return is_object($token) ? ($token->id ?? null) : null;
        } catch (Throwable) {
            return null;
        }
    }
}
