<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Gate;

abstract class ApiController extends Controller
{
    /**
     * Deny unless the host application's Gate allows the ability configured
     * under `api.abilities.{$key}`. The Gate denies everyone until defined.
     */
    protected function authorizeAbility(Request $request, string $key): void
    {
        $ability = $key === 'audit'
            ? config('password-policy.audit.gate_ability', 'view-password-audit-logs')
            : config("password-policy.api.abilities.{$key}");

        Gate::forUser($request->user())->authorize($ability);
    }

    /** @return Model&Authenticatable */
    protected function findUser(string|int $id): Model
    {
        $class = config('password-policy.user_model');

        return $class::query()->findOrFail($id);
    }

    protected function actor(Request $request): ?Authenticatable
    {
        return $request->user();
    }

    protected function message(string $message, int $status = 200, array $extra = [])
    {
        return response()->json(['message' => $message] + $extra, $status);
    }

    protected function error(string $message, string $code, int $status)
    {
        return response()->json(['message' => $message, 'error' => $code], $status);
    }
}
