<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_findings', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('security_session_id')->constrained()->cascadeOnDelete();
            $table->string('module', 64)->index();
            $table->string('severity', 16)->index();
            $table->string('title');
            $table->text('description');
            $table->text('evidence')->nullable();
            $table->text('remediation');
            $table->string('status', 20)->default('open')->index();
            $table->timestamps();

            $table->index(['security_session_id', 'severity']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_findings');
    }
};
