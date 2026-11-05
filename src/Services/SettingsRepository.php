<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use InvalidArgumentException;
use Mainul\PasswordPolicy\Models\PolicySetting;
use Throwable;

/**
 * Runtime settings: a database override on top of the config default.
 *
 * Only keys in OVERRIDABLE can be stored. If the table is missing or the
 * database is unreachable, the config default is used, so a broken database
 * never leaves a setting undefined.
 */
class SettingsRepository
{
    public const CACHE_KEY = 'password-policy:settings';

    /** key => allowed value check */
    public const OVERRIDABLE = [
        'totp.enabled',
        'totp.scope',
        'totp.grace_days',
        'totp.issuer',
        'totp.enabled_at',
    ];

    public function __construct(protected AuditLogger $audit)
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $configDefault = config("password-policy.{$key}", $default);

        // The policy can be pinned in code: the database may not turn it off.
        if ($key === 'totp.enabled' && $configDefault === true && config('password-policy.totp.lock_to_config', false)) {
            return true;
        }

        $overrides = $this->overrides();

        return array_key_exists($key, $overrides) ? $overrides[$key] : $configDefault;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->overrides());
    }

    public function set(string $key, mixed $value, Authenticatable|string|null $actor = null): void
    {
        $this->assertOverridable($key);
        $this->validate($key, $value);

        $old = $this->get($key);

        PolicySetting::updateOrCreate(
            ['key' => $key],
            ['value' => $value, 'updated_by' => $this->actorId($actor)],
        );

        $this->flush();

        $this->audit->log('setting_changed', AuditLogger::OUTCOME_SUCCESS, null, $this->actorId($actor), [
            'key' => $key,
            'old' => $old,
            'new' => $value,
        ]);
    }

    /** Remove an override so the config default applies again. */
    public function forget(string $key, Authenticatable|string|null $actor = null): void
    {
        $this->assertOverridable($key);

        PolicySetting::whereKey($key)->delete();
        $this->flush();

        $this->audit->log('setting_changed', AuditLogger::OUTCOME_SUCCESS, null, $this->actorId($actor), [
            'key' => $key,
            'reset_to_default' => true,
        ]);
    }

    public function flush(): void
    {
        Cache::forget(self::CACHE_KEY);
    }

    /** @return array<string, mixed> */
    protected function overrides(): array
    {
        try {
            return Cache::rememberForever(self::CACHE_KEY, function () {
                return PolicySetting::query()->get()
                    ->mapWithKeys(fn ($row) => [$row->key => $row->value])
                    ->all();
            });
        } catch (Throwable) {
            return [];
        }
    }

    protected function assertOverridable(string $key): void
    {
        if (! in_array($key, self::OVERRIDABLE, true)) {
            throw new InvalidArgumentException("Setting [{$key}] cannot be overridden in the database.");
        }
    }

    protected function validate(string $key, mixed $value): void
    {
        $ok = match ($key) {
            'totp.enabled'    => is_bool($value),
            'totp.scope'      => in_array($value, ['all', 'admins', 'remote'], true),
            'totp.grace_days' => is_int($value) && $value >= 0,
            'totp.issuer'     => $value === null || (is_string($value) && trim($value) !== ''),
            'totp.enabled_at' => $value === null || is_string($value),
            default           => false,
        };

        if (! $ok) {
            throw new InvalidArgumentException("Invalid value for setting [{$key}].");
        }
    }

    protected function actorId(Authenticatable|string|null $actor): ?string
    {
        return $actor instanceof Authenticatable ? (string) $actor->getAuthIdentifier() : $actor;
    }
}
