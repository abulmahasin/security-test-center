<?php

use App\Http\Controllers\AccountSecurityController;
use App\Http\Controllers\AuthenticatedSecurityController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\GuestBoundaryController;
use App\Http\Controllers\LaravelAgentController;
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

    Route::post('/sessions/{session}/identities', [AuthenticatedSecurityController::class, 'storeIdentity'])->name('sessions.identities.store');
    Route::delete('/identities/{identity}', [AuthenticatedSecurityController::class, 'destroyIdentity'])->name('identities.destroy');
    Route::post('/sessions/{session}/access-rules', [AuthenticatedSecurityController::class, 'storeRule'])->name('sessions.access-rules.store');
    Route::delete('/access-rules/{rule}', [AuthenticatedSecurityController::class, 'destroyRule'])->name('access-rules.destroy');

    Route::post('/sessions/{session}/guest-boundaries', [GuestBoundaryController::class, 'store'])->name('sessions.guest-boundaries.store');
    Route::delete('/guest-boundaries/{boundary}', [GuestBoundaryController::class, 'destroy'])->name('guest-boundaries.destroy');

    Route::post('/sessions/{session}/account-tests', [AccountSecurityController::class, 'store'])->name('sessions.account-tests.store');
    Route::delete('/account-tests/{test}', [AccountSecurityController::class, 'destroy'])->name('account-tests.destroy');

    Route::post('/sessions/{session}/laravel-agent-manifests', [LaravelAgentController::class, 'store'])->name('sessions.agent-manifests.store');
    Route::post('/sessions/{session}/laravel-agent-manifests/{manifest}/generate-rules', [LaravelAgentController::class, 'generateRules'])->name('sessions.agent-manifests.generate-rules');
    Route::delete('/laravel-agent-manifests/{manifest}', [LaravelAgentController::class, 'destroy'])->name('agent-manifests.destroy');

    Route::patch('/findings/{finding}/status', [SecurityFindingController::class, 'updateStatus'])->name('findings.status');
});
