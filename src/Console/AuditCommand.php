<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;

/**
 * Read-only view of the audit log for operators with server access (3.7.3).
 * Web access to the logs must go through the configured Gate ability.
 */
class AuditCommand extends Command
{
    protected $signature = 'password-policy:audit
        {--user= : Filter by user id}
        {--event= : Filter by event name}
        {--outcome= : Filter by outcome (success|failure|blocked)}
        {--limit=25 : Number of rows}';

    protected $description = 'Show recent password audit log entries';

    public function handle(): int
    {
        $rows = PasswordAuditLog::query()
            ->when($this->option('user'), fn ($q, $v) => $q->where('user_id', $v))
            ->when($this->option('event'), fn ($q, $v) => $q->where('event', $v))
            ->when($this->option('outcome'), fn ($q, $v) => $q->where('outcome', $v))
            ->orderByDesc('id')
            ->limit((int) $this->option('limit'))
            ->get(['created_at', 'user_id', 'identifier', 'event', 'outcome', 'ip_address']);

        $this->table(
            ['When', 'User', 'Identifier', 'Event', 'Outcome', 'IP'],
            $rows->map(fn ($r) => [
                $r->created_at, $r->user_id, $r->identifier, $r->event, $r->outcome, $r->ip_address,
            ])->all()
        );

        return self::SUCCESS;
    }
}
