<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('mfa_credentials')) {
            return;
        }

        Schema::create('mfa_credentials', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->unique();
            // Encrypted with APP_KEY. TOTP needs the raw secret, so it cannot be hashed.
            $table->text('secret');
            // Null until the user proves the app works; unconfirmed means "not enrolled".
            $table->timestamp('confirmed_at')->nullable();
            // Time-step of the last accepted code. Blocks replaying the same code.
            $table->unsignedBigInteger('last_used_step')->nullable();
            // Hashed single-use backup codes: [{hash, used_at}].
            $table->json('recovery_codes')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('mfa_credentials');
    }
};
