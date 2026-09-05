@extends('layouts.app')

@section('title', 'Login')

@section('content')
<div class="login-wrap">
    <section class="login-card">
        <div class="brand login-brand">
            <span class="brand-mark">ST</span>
            <span><strong>Security Test Center</strong><small>Private workspace</small></span>
        </div>
        <h1>Masuk</h1>
        <p>Dashboard audit keamanan untuk aplikasi yang Anda miliki atau kelola.</p>

        <form method="POST" action="{{ route('login.store') }}" class="form-stack">
            @csrf
            <label>
                <span>Email</span>
                <input type="email" name="email" value="{{ old('email') }}" required autofocus>
            </label>
            <label>
                <span>Password</span>
                <input type="password" name="password" required>
            </label>
            <label class="check-row">
                <input type="checkbox" name="remember" value="1">
                <span>Ingat sesi login</span>
            </label>
            <button class="btn btn-primary btn-block" type="submit">Login</button>
        </form>
    </section>
</div>
@endsection
