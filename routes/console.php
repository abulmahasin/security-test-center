<?php

use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;

Artisan::command('app:create-admin {email} {password} {--name=Administrator}', function (): void {
    $email = strtolower(trim((string) $this->argument('email')));
    $password = (string) $this->argument('password');

    if (! filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $this->error('Email tidak valid.');
        return;
    }

    if (strlen($password) < 12) {
        $this->error('Password minimal 12 karakter.');
        return;
    }

    $user = User::updateOrCreate(
        ['email' => $email],
        [
            'name' => (string) $this->option('name'),
            'password' => Hash::make($password),
            'email_verified_at' => now(),
        ],
    );

    $this->info("Admin siap: {$user->email}");
})->purpose('Create or update the local Security Test Center admin account.');
