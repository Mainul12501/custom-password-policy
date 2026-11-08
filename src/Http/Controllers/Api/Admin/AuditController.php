<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api\Admin;

use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Http\Controllers\Api\ApiController;
use Mainul\PasswordPolicy\Models\PasswordAuditLog;

/** Read-only audit log (3.7.3). Gated by `audit.gate_ability`. */
class AuditController extends ApiController
{
    public function index(Request $request)
    {
        $this->authorizeAbility($request, 'audit');

        $filters = $request->validate([
            'user_id'  => ['nullable'],
            'event'    => ['nullable', 'string', 'max:100'],
            'outcome'  => ['nullable', 'in:success,failure,blocked,alert'],
            'from'     => ['nullable', 'date'],
            'to'       => ['nullable', 'date'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $page = PasswordAuditLog::query()
            ->when($filters['user_id'] ?? null, fn ($q, $v) => $q->where('user_id', $v))
            ->when($filters['event'] ?? null, fn ($q, $v) => $q->where('event', $v))
            ->when($filters['outcome'] ?? null, fn ($q, $v) => $q->where('outcome', $v))
            ->when($filters['from'] ?? null, fn ($q, $v) => $q->where('created_at', '>=', $v))
            ->when($filters['to'] ?? null, fn ($q, $v) => $q->where('created_at', '<=', $v))
            ->orderByDesc('id')
            ->paginate((int) ($filters['per_page'] ?? 25), [
                'id', 'created_at', 'user_id', 'identifier', 'event', 'outcome', 'ip_address', 'user_agent', 'context',
            ]);

        return response()->json($page);
    }
}
