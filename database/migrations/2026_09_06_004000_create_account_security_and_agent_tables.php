<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_account_tests', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->foreignId('security_identity_id')->nullable()->constrained('security_identities')->nullOnDelete();
            $table->string('label', 160);
            $table->string('kind', 40);
            $table->string('path', 255)->nullable();
            $table->text('config_encrypted')->nullable();
            $table->boolean('enabled')->default(true)->index();
            $table->timestamps();

            $table->index(['security_session_id', 'kind']);
        });

        Schema::create('security_agent_manifests', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->string('source_label', 120)->default('Laravel Application');
            $table->string('framework', 40)->default('laravel');
            $table->string('framework_version', 40)->nullable();
            $table->unsignedInteger('routes_count')->default(0);
            $table->json('manifest');
            $table->timestamp('received_at')->nullable();
            $table->timestamps();

            $table->index(['security_session_id', 'received_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_agent_manifests');
        Schema::dropIfExists('security_account_tests');
    }
};
