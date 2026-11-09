<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('service_accounts')) {
            return;
        }

        Schema::create('service_accounts', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('user_id')->unique();
            $table->string('owner');
            $table->text('purpose');
            $table->unsignedInteger('rotation_days')->default(90);
            $table->timestamp('last_rotated_at')->nullable();
            $table->timestamp('next_rotation_at')->nullable()->index();
            // User ids of people who know the password. Used when someone leaves.
            $table->json('known_by')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('service_accounts');
    }
};
