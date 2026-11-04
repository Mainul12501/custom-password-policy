<?php

namespace Mainul\PasswordPolicy\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Mainul\PasswordPolicy\Contracts\GeoResolver;
use Mainul\PasswordPolicy\Events\UnusualLoginDetected;
use Mainul\PasswordPolicy\Models\KnownLogin;

/**
 * Spots unusual login activity and raises alerts (Policy 3.7.4):
 *  - repeated failures against one account within a short window;
 *  - a successful login from a network (or country) the user has not used.
 *
 * Only a keyed hash of the IP network prefix is stored, never the address.
 */
class AnomalyDetector
{
    public const REASON_FAILURES = 'repeated_failures';
    public const REASON_NEW_NETWORK = 'new_network';
    public const REASON_NEW_COUNTRY = 'new_country';

    public function __construct(protected AuditLogger $audit)
    {
    }

    /** Call for each failed login. Alerts once, when the threshold is reached. */
    public function inspectFailure(?Authenticatable $user, ?string $identifier, ?string $ip): void
    {
        if (! config('password-policy.anomaly.enabled', true)) {
            return;
        }

        $subject = $user ? 'u' . $user->getAuthIdentifier() : 'i' . strtolower((string) $identifier);
        if ($subject === 'i') {
            return;
        }

        $window = max(1, (int) config('password-policy.anomaly.window_minutes', 10)) * 60;
        $key = 'password-policy:failures:' . sha1($subject);

        Cache::add($key, 0, $window);
        $count = Cache::increment($key);

        if ($count === (int) config('password-policy.anomaly.failure_threshold', 3)) {
            $this->raise($user, $identifier, [self::REASON_FAILURES], $ip);
        }
    }

    /** Call for each successful login. The user's first login sets the baseline. */
    public function inspectLogin(Authenticatable $user, ?string $ip): void
    {
        if (! config('password-policy.anomaly.enabled', true) || $ip === null) {
            return;
        }

        $hash = $this->prefixHash($ip);
        if ($hash === null) {
            return;
        }

        $country = $this->country($ip);
        $known = KnownLogin::where('user_id', $user->getAuthIdentifier())->get();
        $reasons = [];

        if ($known->isNotEmpty()) {
            if (! $known->contains('prefix_hash', $hash)) {
                $reasons[] = self::REASON_NEW_NETWORK;
            }

            $knownCountries = $known->pluck('country')->filter();
            if ($country && $knownCountries->isNotEmpty() && ! $knownCountries->contains($country)) {
                $reasons[] = self::REASON_NEW_COUNTRY;
            }
        }

        $row = $known->firstWhere('prefix_hash', $hash);
        if ($row) {
            $row->update(['last_seen_at' => now(), 'country' => $row->country ?? $country]);
        } else {
            KnownLogin::create([
                'user_id'       => $user->getAuthIdentifier(),
                'prefix_hash'   => $hash,
                'country'       => $country,
                'first_seen_at' => now(),
                'last_seen_at'  => now(),
            ]);
        }

        if ($reasons !== []) {
            $this->raise($user, null, $reasons, $ip);
        }
    }

    /** Keyed hash of the IP's network prefix, or null for an invalid address. */
    public function prefixHash(string $ip): ?string
    {
        $binary = @inet_pton($ip);

        if ($binary === false) {
            return null;
        }

        $bits = strlen($binary) === 4
            ? (int) config('password-policy.anomaly.ipv4_prefix', 24)
            : (int) config('password-policy.anomaly.ipv6_prefix', 48);

        $masked = '';
        for ($i = 0; $i < strlen($binary); $i++) {
            $keep = max(0, min(8, $bits - ($i * 8)));
            $masked .= chr(ord($binary[$i]) & ((0xFF << (8 - $keep)) & 0xFF));
        }

        return hash_hmac('sha256', bin2hex($masked) . '/' . $bits, (string) config('app.key'));
    }

    protected function country(string $ip): ?string
    {
        $class = config('password-policy.anomaly.geo_resolver');

        if (! $class) {
            return null;
        }

        $country = app($class)->country($ip);

        return $country ? strtoupper(substr($country, 0, 2)) : null;
    }

    protected function raise(?Authenticatable $user, ?string $identifier, array $reasons, ?string $ip): void
    {
        $this->audit->log('unusual_login', AuditLogger::OUTCOME_ALERT, $user, $identifier, ['reasons' => $reasons]);

        event(new UnusualLoginDetected($user, $identifier, $reasons, $ip));
    }
}
