<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_sessions', function (Blueprint $table): void {
            $table->foreignId('baseline_session_id')->nullable()->after('user_id')->constrained('security_sessions')->nullOnDelete();
            $table->string('grade', 4)->nullable()->after('score');
            $table->unsignedTinyInteger('compliance_score')->nullable()->after('grade');
            $table->integer('risk_delta')->nullable()->after('compliance_score');
            $table->unsignedInteger('new_findings_count')->default(0)->after('risk_delta');
            $table->unsignedInteger('resolved_findings_count')->default(0)->after('new_findings_count');
            $table->string('schedule_frequency', 24)->nullable()->after('config');
            $table->timestamp('next_run_at')->nullable()->index()->after('schedule_frequency');
            $table->timestamp('last_scheduled_at')->nullable()->after('next_run_at');
            $table->json('metadata')->nullable()->after('error_message');
        });

        Schema::table('security_findings', function (Blueprint $table): void {
            $table->string('fingerprint', 64)->nullable()->index()->after('module');
            $table->string('change_type', 24)->default('new')->index()->after('fingerprint');
        });
    }

    public function down(): void
    {
        Schema::table('security_findings', function (Blueprint $table): void {
            $table->dropIndex(['fingerprint']);
            $table->dropIndex(['change_type']);
            $table->dropColumn(['fingerprint', 'change_type']);
        });

        Schema::table('security_sessions', function (Blueprint $table): void {
            $table->dropForeign(['baseline_session_id']);
            $table->dropIndex(['next_run_at']);
            $table->dropColumn([
                'baseline_session_id', 'grade', 'compliance_score', 'risk_delta',
                'new_findings_count', 'resolved_findings_count', 'schedule_frequency',
                'next_run_at', 'last_scheduled_at', 'metadata',
            ]);
        });
    }
};
