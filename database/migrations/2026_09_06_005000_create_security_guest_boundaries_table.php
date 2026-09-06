<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_guest_boundaries', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->string('label', 160);
            $table->string('path', 500);
            $table->string('auth_mode', 24)->default('session');
            $table->text('business_context')->nullable();
            $table->boolean('enabled')->default(true);
            $table->timestamps();

            $table->unique(['security_session_id', 'path', 'auth_mode'], 'guest_boundary_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_guest_boundaries');
    }
};
