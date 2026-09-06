<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_identities', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->string('label', 120);
            $table->string('expected_role', 80)->nullable();
            $table->string('auth_type', 24)->default('form');
            $table->string('login_path', 255)->default('/login');
            $table->string('username_field', 80)->default('email');
            $table->text('username');
            $table->text('password_encrypted')->nullable();
            $table->text('bearer_token_encrypted')->nullable();
            $table->string('success_path', 255)->default('/');
            $table->boolean('enabled')->default(true)->index();
            $table->timestamps();
        });

        Schema::create('security_access_rules', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->foreignId('security_identity_id')->constrained('security_identities')->cascadeOnDelete();
            $table->string('label', 160);
            $table->string('path', 255);
            $table->string('expectation', 24)->default('denied');
            $table->timestamps();

            $table->index(['security_session_id', 'security_identity_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_access_rules');
        Schema::dropIfExists('security_identities');
    }
};
