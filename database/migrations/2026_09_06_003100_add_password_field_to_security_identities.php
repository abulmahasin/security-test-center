<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_identities', function (Blueprint $table): void {
            $table->string('password_field', 80)->default('password')->after('username_field');
        });
    }

    public function down(): void
    {
        Schema::table('security_identities', function (Blueprint $table): void {
            $table->dropColumn('password_field');
        });
    }
};
