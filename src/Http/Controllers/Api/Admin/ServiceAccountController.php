<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api\Admin;

use Illuminate\Http\Request;
use Mainul\PasswordPolicy\Http\Controllers\Api\ApiController;
use Mainul\PasswordPolicy\Models\ServiceAccount;
use Mainul\PasswordPolicy\Services\ServiceAccountService;
use RuntimeException;
use Throwable;

/** Service accounts: owner, purpose and password rotation (3.9.3, 3.9.4). */
class ServiceAccountController extends ApiController
{
    public function index(Request $request)
    {
        $this->authorizeAbility($request, 'service_accounts');

        $accounts = ServiceAccount::query()
            ->when($request->boolean('due'), fn ($q) => $q->due())
            ->orderBy('next_rotation_at')
            ->get();

        return response()->json(['data' => $accounts->map(fn ($a) => $this->present($a))->values()]);
    }

    public function store(Request $request, ServiceAccountService $service)
    {
        $this->authorizeAbility($request, 'service_accounts');

        $data = $request->validate([
            'user_id'       => ['required'],
            'owner'         => ['required', 'string', 'max:255'],
            'purpose'       => ['required', 'string', 'max:255'],
            'rotation_days' => ['nullable', 'integer', 'min:1', 'max:3650'],
            'known_by'      => ['nullable', 'array'],
            'known_by.*'    => ['integer'],
        ]);

        $account = $service->register(
            $this->findUser($data['user_id']),
            $data['owner'],
            $data['purpose'],
            $data['rotation_days'] ?? null,
            $data['known_by'] ?? [],
        );

        return response()->json(['data' => $this->present($account)], 201);
    }

    public function update(Request $request, string $user, ServiceAccountService $service)
    {
        $this->authorizeAbility($request, 'service_accounts');

        $data = $request->validate([
            'owner'         => ['sometimes', 'string', 'max:255'],
            'purpose'       => ['sometimes', 'string', 'max:255'],
            'rotation_days' => ['sometimes', 'integer', 'min:1', 'max:3650'],
            'known_by'      => ['sometimes', 'array'],
            'known_by.*'    => ['integer'],
        ]);

        try {
            $account = $service->update($this->findUser($user), $data);
        } catch (RuntimeException $e) {
            return $this->error($e->getMessage(), 'not_a_service_account', 404);
        }

        return response()->json(['data' => $this->present($account)]);
    }

    public function destroy(Request $request, string $user, ServiceAccountService $service)
    {
        $this->authorizeAbility($request, 'service_accounts');

        return $service->remove($this->findUser($user))
            ? $this->message('Service account removed.')
            : $this->error('This user is not a registered service account.', 'not_a_service_account', 404);
    }

    /** Email the owners and `notify_recipients` about overdue rotations. */
    public function notifyDue(Request $request, ServiceAccountService $service)
    {
        $this->authorizeAbility($request, 'service_accounts');

        return response()->json(['notified' => $service->notifyDue()]);
    }

    /** Rotate one account. The new secret goes to the vault and is never returned. */
    public function rotate(Request $request, string $user, ServiceAccountService $service)
    {
        $this->authorizeAbility($request, 'service_accounts');

        try {
            $service->rotate($this->findUser($user));
        } catch (RuntimeException $e) {
            return $this->error($e->getMessage(), 'rotation_refused', 422);
        }

        return $this->message('Password rotated.');
    }

    /** Rotate every overdue account; one failure does not stop the others. */
    public function rotateDue(Request $request, ServiceAccountService $service)
    {
        $this->authorizeAbility($request, 'service_accounts');

        $results = [];

        foreach ($service->due() as $account) {
            try {
                $service->rotate($this->findUser($account->user_id));
                $results[] = ['user_id' => $account->user_id, 'rotated' => true];
            } catch (RuntimeException $e) {
                $results[] = ['user_id' => $account->user_id, 'rotated' => false, 'reason' => $e->getMessage()];
            } catch (Throwable $e) {
                report($e);
                $results[] = ['user_id' => $account->user_id, 'rotated' => false, 'reason' => 'Rotation failed.'];
            }
        }

        return response()->json(['data' => $results]);
    }

    protected function present(ServiceAccount $account): array
    {
        return [
            'user_id'          => $account->user_id,
            'owner'            => $account->owner,
            'purpose'          => $account->purpose,
            'rotation_days'    => (int) $account->rotation_days,
            'last_rotated_at'  => $account->last_rotated_at?->toIso8601String(),
            'next_rotation_at' => $account->next_rotation_at?->toIso8601String(),
            'due'              => $account->next_rotation_at !== null && $account->next_rotation_at->isPast(),
            'known_by'         => $account->known_by ?? [],
        ];
    }
}
