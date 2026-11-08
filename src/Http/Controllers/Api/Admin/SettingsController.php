<?php

namespace Mainul\PasswordPolicy\Http\Controllers\Api\Admin;

use Illuminate\Http\Request;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Http\Controllers\Api\ApiController;
use Mainul\PasswordPolicy\Services\SettingsRepository;

/**
 * Runtime settings stored in the database (authenticator-app policy, API
 * on/off, API guard). The database value wins over the config default.
 */
class SettingsController extends ApiController
{
    public function __construct(protected SettingsRepository $settings)
    {
    }

    public function index(Request $request)
    {
        $this->authorizeAbility($request, 'settings');

        return response()->json(['data' => $this->all()]);
    }

    /** Body: {"settings": {"totp.enabled": true, "api.guard": "api"}} */
    public function update(Request $request)
    {
        $this->authorizeAbility($request, 'settings');
        $data = $request->validate(['settings' => ['required', 'array', 'min:1']]);
        $actor = $this->actorId($request);

        // Check everything first so one bad value changes nothing.
        foreach ($data['settings'] as $key => $value) {
            if ($key === 'totp.enabled_at') {
                return $this->invalid($key, 'totp.enabled_at is recorded automatically when totp.enabled is switched on.');
            }

            try {
                $this->settings->assertValid((string) $key, $value);
            } catch (InvalidArgumentException $e) {
                return $this->invalid((string) $key, $e->getMessage());
            }
        }

        foreach ($data['settings'] as $key => $value) {
            $key === 'totp.enabled'
                ? $this->switchTotp($value, $actor)
                : $this->settings->set($key, $value, $actor);
        }

        if (array_key_exists('totp.enabled', $data['settings'])
            && $data['settings']['totp.enabled'] === false
            && $this->settings->get('totp.enabled', false)) {
            return $this->error('Still enabled: totp.lock_to_config is true and the config enables it. Change the config file.', 'locked_to_config', 409);
        }

        return response()->json(['data' => $this->all()]);
    }

    /** Remove the database override so the config default applies again. */
    public function destroy(Request $request, string $key)
    {
        $this->authorizeAbility($request, 'settings');

        try {
            $this->settings->forget($key, $this->actorId($request));
        } catch (InvalidArgumentException $e) {
            return $this->invalid($key, $e->getMessage());
        }

        return response()->json(['data' => $this->all()]);
    }

    /** Same behaviour as `password-policy:totp --enable/--disable`. */
    protected function switchTotp(mixed $value, ?string $actor): void
    {
        if ($value === true && ! $this->settings->get('totp.enabled', false)) {
            // Starts the enrolment grace clock only when this really switches it on.
            $this->settings->set('totp.enabled_at', now()->toIso8601String(), $actor);
        }

        $this->settings->set('totp.enabled', $value, $actor);

        if ($value === false) {
            $this->settings->forget('totp.enabled_at', $actor);
        }
    }

    /** @return array<string,array{value:mixed,source:string}> */
    protected function all(): array
    {
        $out = [];

        foreach (SettingsRepository::OVERRIDABLE as $key) {
            $out[$key] = [
                'value'  => $this->settings->get($key),
                'source' => $this->settings->has($key) ? 'database' : 'config',
            ];
        }

        return $out;
    }

    protected function actorId(Request $request): ?string
    {
        $user = $request->user();

        return $user ? (string) $user->getAuthIdentifier() : null;
    }

    protected function invalid(string $key, string $message)
    {
        return response()->json([
            'message' => $message,
            'errors'  => ['settings' => [$message]],
            'key'     => $key,
        ], 422);
    }
}
