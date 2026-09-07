<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        User::firstOrCreate(
            ['email' => 'admin@security.test'],
            [
                'name' => 'Admin Tester',
                'password' => Hash::make('password'),
                'email_verified_at' => now(),
            ]
        );
    }
}