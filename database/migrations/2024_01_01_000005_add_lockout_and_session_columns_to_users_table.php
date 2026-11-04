<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->boolean('is_permanently_locked')->default(false);
            $table->boolean('requires_identity_verification')->default(false);
            $table->timestamp('last_failed_login_at')->nullable();
            // Bumped to invalidate every existing session of the user.
            $table->unsignedInteger('session_version')->default(0);
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'is_permanently_locked',
                'requires_identity_verification',
                'last_failed_login_at',
                'session_version',
            ]);
        });
    }
};
