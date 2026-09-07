<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    public function run(): void
    {
        User::create([
            'name' => 'Admin Tester',
            'email' => 'admin@security.test',
            'password' => Hash::make('password'),
            'email_verified_at' => now(),
        ]);

        // Atau buat beberapa dummy tambahan pakai factory (jika ada)
        User::factory()->count(3)->create();
    }
}