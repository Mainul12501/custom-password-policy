<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('password_known_logins')) {
            return;
        }

        Schema::create('password_known_logins', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id');
            // Keyed hash of the IP network prefix, never the address itself.
            $table->string('prefix_hash', 64);
            $table->string('country', 2)->nullable();
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');

            $table->unique(['user_id', 'prefix_hash']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('password_known_logins');
    }
};
