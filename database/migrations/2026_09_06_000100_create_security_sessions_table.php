<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_sessions', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('name', 120);
            $table->text('target_url');
            $table->string('environment', 24)->default('production');
            $table->string('profile', 24)->default('balanced');
            $table->string('status', 24)->default('draft')->index();
            $table->unsignedTinyInteger('progress')->default(0);
            $table->string('current_stage')->nullable();
            $table->unsignedTinyInteger('score')->nullable();
            $table->json('selected_modules');
            $table->json('config')->nullable();
            $table->string('verification_token', 80);
            $table->timestamp('verified_at')->nullable()->index();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->text('error_message')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_sessions');
    }
};
