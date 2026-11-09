<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            if (! Schema::hasColumn('users', 'is_permanently_locked')) {
                $table->boolean('is_permanently_locked')->default(false);
            }
            if (! Schema::hasColumn('users', 'requires_identity_verification')) {
                $table->boolean('requires_identity_verification')->default(false);
            }
            if (! Schema::hasColumn('users', 'last_failed_login_at')) {
                $table->timestamp('last_failed_login_at')->nullable();
            }
            if (! Schema::hasColumn('users', 'session_version')) {
                // Bumped to invalidate every existing session of the user.
                $table->unsignedInteger('session_version')->default(0);
            }
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        $columns = array_values(array_filter([
            'is_permanently_locked',
            'requires_identity_verification',
            'last_failed_login_at',
            'session_version',
        ], fn (string $column) => Schema::hasColumn('users', $column)));

        if ($columns !== []) {
            Schema::table('users', function (Blueprint $table) use ($columns) {
                $table->dropColumn($columns);
            });
        }
    }
};
