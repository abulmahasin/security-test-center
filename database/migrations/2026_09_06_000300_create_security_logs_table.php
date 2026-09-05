<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_logs', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->string('level', 16)->default('info');
            $table->text('message');
            $table->json('meta')->nullable();
            $table->timestamp('created_at')->useCurrent();

            $table->index(['security_session_id', 'id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_logs');
    }
};
