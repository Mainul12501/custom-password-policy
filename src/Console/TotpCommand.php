<?php

namespace Mainul\PasswordPolicy\Console;

use Illuminate\Console\Command;
use Mainul\PasswordPolicy\Models\MfaCredential;
use Mainul\PasswordPolicy\Services\SettingsRepository;
use Mainul\PasswordPolicy\Services\TotpEnrollmentService;

class TotpCommand extends Command
{
    protected $signature = 'password-policy:totp
        {--enable : Require an authenticator app (recorded in the database)}
        {--disable : Stop requiring an authenticator app}
        {--status : Show the current state}
        {--reset= : Wipe the authenticator app of a user (id or email) who lost their device}
        {--scope= : Who must use it: all, admins or remote}
        {--grace-days= : Days new requirement waits before blocking unenrolled users}
        {--actor= : Who is making this change (recorded in the audit log)}';

    protected $description = 'Turn the authenticator-app login on or off, show its status, or reset a user';

    public function handle(SettingsRepository $settings, TotpEnrollmentService $enrollment): int
    {
        $actor = $this->option('actor');
        $acted = false;

        if ($this->option('enable') && $this->option('disable')) {
            $this->error('Use either --enable or --disable, not both.');

            return self::FAILURE;
        }

        if ($scope = $this->option('scope')) {
            if (! in_array($scope, ['all', 'admins', 'remote'], true)) {
                $this->error('--scope must be all, admins or remote.');

                return self::FAILURE;
            }
            $settings->set('totp.scope', $scope, $actor);
            $acted = true;
        }

        if (($days = $this->option('grace-days')) !== null) {
            if (! ctype_digit((string) $days)) {
                $this->error('--grace-days must be a whole number.');

                return self::FAILURE;
            }
            $settings->set('totp.grace_days', (int) $days, $actor);
            $acted = true;
        }

        if ($this->option('enable')) {
            // Only start the grace clock when this really switches it on.
            if (! $settings->get('totp.enabled', false)) {
                $settings->set('totp.enabled_at', now()->toIso8601String(), $actor);
            }
            $settings->set('totp.enabled', true, $actor);
            $this->info('Authenticator app login is now required.');
            $acted = true;
        }

        if ($this->option('disable')) {
            $settings->set('totp.enabled', false, $actor);
            $settings->forget('totp.enabled_at', $actor);

            if ($settings->get('totp.enabled', false)) {
                $this->error('Still enabled: totp.lock_to_config is true and config enables it. Change the config file.');

                return self::FAILURE;
            }

            $this->info('Authenticator app login is now off.');
            $acted = true;
        }

        if ($needle = $this->option('reset')) {
            $user = $this->findUser($needle);

            if (! $user) {
                $this->error("No user found for [{$needle}].");

                return self::FAILURE;
            }

            $enrollment->reset($user, $actor);
            $this->info("Authenticator app reset for [{$user->getKey()}]. They will set it up again at next login.");
            $acted = true;
        }

        if ($this->option('status') || ! $acted) {
            $this->status($settings);
        }

        return self::SUCCESS;
    }

    protected function status(SettingsRepository $settings): void
    {
        $this->table(['Setting', 'Value', 'Source'], collect([
            'totp.enabled'    => $settings->get('totp.enabled', false),
            'totp.scope'      => $settings->get('totp.scope', 'all'),
            'totp.grace_days' => $settings->get('totp.grace_days', 0),
            'totp.enabled_at' => $settings->get('totp.enabled_at'),
        ])->map(fn ($value, $key) => [
            $key,
            is_bool($value) ? ($value ? 'true' : 'false') : (string) ($value ?? '-'),
            $settings->has($key) ? 'database' : 'config',
        ])->values()->all());

        $this->line('Users with an authenticator app: ' . MfaCredential::whereNotNull('confirmed_at')->count());
    }

    protected function findUser(string $needle)
    {
        $class = config('password-policy.user_model');

        return $class::query()
            ->where(config('password-policy.columns.email', 'email'), $needle)
            ->orWhere((new $class())->getKeyName(), $needle)
            ->first();
    }
}
