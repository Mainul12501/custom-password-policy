<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;
use Mainul\PasswordPolicy\Support\Redactor;
use Throwable;

/**
 * Writes password-related events to the audit log (Policy 3.7.1).
 *
 * Secrets are redacted from the context, and a failure to write the log is
 * reported but never allowed to break a login or password change.
 */
class AuditLogger
{
    public const OUTCOME_SUCCESS = 'success';
    public const OUTCOME_FAILURE = 'failure';
    public const OUTCOME_BLOCKED = 'blocked';
    public const OUTCOME_ALERT = 'alert';

    public function log(
        string $event,
        string $outcome,
        ?Authenticatable $user = null,
        ?string $identifier = null,
        array $context = [],
    ): ?PasswordAuditLog {
        if (! config('password-policy.audit.enabled', true)) {
            return null;
        }

        try {
            $request = app()->bound('request') ? request() : null;

            if ($identifier === null && $user !== null) {
                $emailColumn = config('password-policy.columns.email', 'email');
                $identifier = $user->{$emailColumn} ?? null;
            }

            return PasswordAuditLog::create([
                'user_id'    => $user?->getAuthIdentifier(),
                'identifier' => $identifier,
                'event'      => $event,
                'outcome'    => $outcome,
                'ip_address' => $request?->ip(),
                'user_agent' => $request ? mb_substr((string) $request->userAgent(), 0, 512) : null,
                'context'    => $context === [] ? null : Redactor::redact($context),
            ]);
        } catch (Throwable $e) {
            report($e);

            return null;
        }
    }
}
