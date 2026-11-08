<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api\Admin;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Mainul\PasswordPolicy\Http\Controllers\Api\ApiController;
use Mainul\PasswordPolicy\Jobs\ScanDefaultPasswords;
use Mainul\PasswordPolicy\Services\DefaultPasswordScanner;
use Mainul\PasswordPolicy\Support\ComplianceChecker;

/** The same self-test and go-live checks the commands run. */
class ComplianceController extends ApiController
{
    /** Same checks as `password-policy:check`. */
    public function check(Request $request, ComplianceChecker $checker)
    {
        $this->authorizeAbility($request, 'compliance');

        $checks = collect($checker->run())->map(fn ($row) => [
            'check'  => $row[0],
            'status' => $row[1],
            'detail' => $row[2],
        ])->values();

        return response()->json([
            'passed' => $checks->where('status', 'fail')->isEmpty(),
            'counts' => [
                'pass' => $checks->where('status', 'pass')->count(),
                'warn' => $checks->where('status', 'warn')->count(),
                'fail' => $checks->where('status', 'fail')->count(),
            ],
            'data'   => $checks,
        ]);
    }

    /**
     * Find accounts using a known default password (3.9.5). With `user_id` the
     * answer is immediate; without it the whole table is scanned in the
     * background and the result is read from the returned `scan_id`.
     */
    public function scanDefaults(Request $request, DefaultPasswordScanner $scanner)
    {
        $this->authorizeAbility($request, 'users');

        $data = $request->validate([
            'user_id' => ['nullable'],
            'flag'    => ['sometimes', 'boolean'],
        ]);
        $flag = (bool) ($data['flag'] ?? false);

        if (! empty($data['user_id'])) {
            $found = $scanner->scan($flag, $data['user_id']);

            return response()->json(['status' => 'finished', 'flagged' => $flag, 'found' => $found]);
        }

        $scanId = (string) Str::uuid();
        Cache::put(ScanDefaultPasswords::cacheKey($scanId), ['status' => 'queued', 'scan_id' => $scanId], now()->addHours(ScanDefaultPasswords::TTL_HOURS));
        ScanDefaultPasswords::dispatch($scanId, $flag);

        return response()->json(['status' => 'queued', 'scan_id' => $scanId], 202);
    }

    public function scanResult(Request $request, string $scanId)
    {
        $this->authorizeAbility($request, 'users');

        $state = Cache::get(ScanDefaultPasswords::cacheKey($scanId));

        return $state
            ? response()->json($state)
            : $this->error('No scan with that id, or it has expired.', 'scan_not_found', 404);
    }
}
