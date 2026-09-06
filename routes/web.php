<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\SecurityFindingController;
use App\Http\Controllers\SecuritySessionController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function (): void {
    Route::get('/login', [AuthController::class, 'create'])->name('login');
    Route::post('/login', [AuthController::class, 'store'])->name('login.store');
});

Route::middleware('auth')->group(function (): void {
    Route::post('/logout', [AuthController::class, 'destroy'])->name('logout');

    Route::get('/', DashboardController::class)->name('dashboard');

    Route::get('/sessions/create', [SecuritySessionController::class, 'create'])->name('sessions.create');
    Route::post('/sessions', [SecuritySessionController::class, 'store'])->name('sessions.store');
    Route::get('/sessions/{session}', [SecuritySessionController::class, 'show'])->name('sessions.show');
    Route::post('/sessions/{session}/verify', [SecuritySessionController::class, 'verify'])->name('sessions.verify');
    Route::patch('/sessions/{session}/monitoring', [SecuritySessionController::class, 'updateMonitoring'])->name('sessions.monitoring');
    Route::post('/sessions/{session}/run', [SecuritySessionController::class, 'run'])->name('sessions.run');
    Route::get('/sessions/{session}/status', [SecuritySessionController::class, 'status'])->name('sessions.status');
    Route::get('/sessions/{session}/report.json', [SecuritySessionController::class, 'report'])->name('sessions.report');

    Route::patch('/findings/{finding}/status', [SecurityFindingController::class, 'updateStatus'])->name('findings.status');
});
