<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('password_audit_logs')) {
            return;
        }

        Schema::create('password_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('identifier')->nullable();
            $table->string('event', 64);
            $table->string('outcome', 16);
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent', 512)->nullable();
            $table->json('context')->nullable();
            $table->timestamp('created_at')->useCurrent();

            $table->index(['user_id', 'created_at']);
            $table->index(['ip_address', 'created_at']);
            $table->index('event');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('password_audit_logs');
    }
};
