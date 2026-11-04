<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->boolean('must_change_password')->default(false);
            $table->timestamp('disabled_at')->nullable();
            $table->string('disabled_reason')->nullable();
            $table->timestamp('locked_until')->nullable();
            $table->unsignedInteger('failed_login_count')->default(0);
            $table->unsignedTinyInteger('lockout_level')->default(0);
        });

        // Existing users have no recorded change date, which the expiry service
        // treats as "expired". Start their clock now so upgrading does not
        // expire (or later auto-disable) every existing account.
        DB::table('users')
            ->whereNull('password_changed_at')
            ->update(['password_changed_at' => now()]);
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'must_change_password',
                'disabled_at',
                'disabled_reason',
                'locked_until',
                'failed_login_count',
                'lockout_level',
            ]);
        });
    }
};
