<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            if (! Schema::hasColumn('users', 'must_change_password')) {
                $table->boolean('must_change_password')->default(false);
            }
            if (! Schema::hasColumn('users', 'disabled_at')) {
                $table->timestamp('disabled_at')->nullable();
            }
            if (! Schema::hasColumn('users', 'disabled_reason')) {
                $table->string('disabled_reason')->nullable();
            }
            if (! Schema::hasColumn('users', 'locked_until')) {
                $table->timestamp('locked_until')->nullable();
            }
            if (! Schema::hasColumn('users', 'failed_login_count')) {
                $table->unsignedInteger('failed_login_count')->default(0);
            }
            if (! Schema::hasColumn('users', 'lockout_level')) {
                $table->unsignedTinyInteger('lockout_level')->default(0);
            }
        });

        // Existing users have no recorded change date, which the expiry service
        // treats as "expired". Start their clock now so upgrading does not
        // expire (or later auto-disable) every existing account.
        if (Schema::hasColumn('users', 'password_changed_at')) {
            DB::table('users')
                ->whereNull('password_changed_at')
                ->update(['password_changed_at' => now()]);
        }
    }

    public function down(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        $columns = array_values(array_filter([
            'must_change_password',
            'disabled_at',
            'disabled_reason',
            'locked_until',
            'failed_login_count',
            'lockout_level',
        ], fn (string $column) => Schema::hasColumn('users', $column)));

        if ($columns !== []) {
            Schema::table('users', function (Blueprint $table) use ($columns) {
                $table->dropColumn($columns);
            });
        }
    }
};
