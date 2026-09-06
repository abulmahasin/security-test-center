<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_sessions', function (Blueprint $table): void {
            $table->boolean('monitoring_enabled')->default(false)->after('schedule_frequency')->index();
            $table->unsignedInteger('schedule_interval_minutes')->nullable()->after('monitoring_enabled');
        });
    }

    public function down(): void
    {
        Schema::table('security_sessions', function (Blueprint $table): void {
            $table->dropIndex(['monitoring_enabled']);
            $table->dropColumn(['monitoring_enabled', 'schedule_interval_minutes']);
        });
    }
};
