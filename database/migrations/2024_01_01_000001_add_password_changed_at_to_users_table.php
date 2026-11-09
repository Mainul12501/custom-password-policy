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
            if (! Schema::hasColumn('users', 'password_changed_at')) {
                $table->timestamp('password_changed_at')->nullable()->after('password');
            }
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('users')) {
            return;
        }

        $columns = array_values(array_filter([
            'password_changed_at',
        ], fn (string $column) => Schema::hasColumn('users', $column)));

        if ($columns !== []) {
            Schema::table('users', function (Blueprint $table) use ($columns) {
                $table->dropColumn($columns);
            });
        }
    }
};
