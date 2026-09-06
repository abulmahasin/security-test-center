<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_test_identities', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained('security_sessions')->cascadeOnDelete();
            $table->string('name', 100);
            $table->string('role_label', 80)->nullable();
            $table->string('auth_type', 24);
            $table->text('credentials');
            $table->boolean('enabled')->default(true)->index();
            $table->timestamp('last_verified_at')->nullable();
            $table->string('last_auth_status', 32)->nullable();
            $table->timestamps();

            $table->index(['security_session_id', 'enabled']);
        });

        Schema::create('security_access_cases', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained('security_sessions')->cascadeOnDelete();
            $table->foreignId('security_test_identity_id')->constrained('security_test_identities')->cascadeOnDelete();
            $table->string('name', 140);
            $table->string('kind', 32)->default('authorization');
            $table->string('method', 10)->default('GET');
            $table->string('path', 1000);
            $table->string('expected_policy', 24)->default('forbidden');
            $table->text('business_context')->nullable();
            $table->boolean('enabled')->default(true)->index();
            $table->timestamps();
        });

        Schema::create('security_access_results', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_access_case_id')->constrained('security_access_cases')->cascadeOnDelete();
            $table->foreignId('security_session_id')->constrained('security_sessions')->cascadeOnDelete();
            $table->foreignId('security_test_identity_id')->constrained('security_test_identities')->cascadeOnDelete();
            $table->string('outcome', 24)->index();
            $table->unsignedSmallInteger('status_code')->nullable();
            $table->string('severity', 16)->nullable();
            $table->text('summary');
            $table->text('evidence')->nullable();
            $table->text('remediation')->nullable();
            $table->unsignedInteger('response_bytes')->nullable();
            $table->unsignedInteger('duration_ms')->nullable();
            $table->timestamp('executed_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_access_results');
        Schema::dropIfExists('security_access_cases');
        Schema::dropIfExists('security_test_identities');
    }
};
