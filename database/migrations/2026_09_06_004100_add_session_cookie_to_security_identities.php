<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_identities', function (Blueprint $table): void {
            $table->text('session_cookie_encrypted')->nullable()->after('bearer_token_encrypted');
        });
    }

    public function down(): void
    {
        Schema::table('security_identities', function (Blueprint $table): void {
            $table->dropColumn('session_cookie_encrypted');
        });
    }
};
