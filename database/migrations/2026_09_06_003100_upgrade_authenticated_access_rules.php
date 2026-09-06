<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_access_rules', function (Blueprint $table): void {
            $table->string('kind', 24)->default('authorization')->after('label');
            $table->text('business_context')->nullable()->after('expectation');
        });
    }

    public function down(): void
    {
        Schema::table('security_access_rules', function (Blueprint $table): void {
            $table->dropColumn(['kind', 'business_context']);
        });
    }
};
