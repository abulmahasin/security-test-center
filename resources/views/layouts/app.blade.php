<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Security Test Center') — {{ config('app.name') }}</title>
    <link rel="stylesheet" href="{{ asset('css/app.css') }}">
    <link rel="stylesheet" href="{{ asset('css/posture.css') }}">
</head>
<body>
<div class="shell">
    @auth
        <aside class="sidebar">
            <a href="{{ route('dashboard') }}" class="brand">
                <span class="brand-mark">ST</span>
                <span><strong>Security Test</strong><small>Continuous Posture Center</small></span>
            </a>

            <nav>
                <a href="{{ route('dashboard') }}" class="{{ request()->routeIs('dashboard') ? 'active' : '' }}">Security Operations</a>
                <a href="{{ route('sessions.create') }}" class="{{ request()->routeIs('sessions.create') ? 'active' : '' }}">New Assessment</a>
            </nav>

            <div class="sidebar-bottom">
                <div class="userbox">
                    <strong>{{ auth()->user()->name }}</strong>
                    <span>{{ auth()->user()->email }}</span>
                </div>
                <form method="POST" action="{{ route('logout') }}">
                    @csrf
                    <button class="btn btn-ghost btn-block" type="submit">Logout</button>
                </form>
            </div>
        </aside>
    @endauth

    <main class="{{ auth()->check() ? 'content' : 'content-auth' }}">
        @auth
            <header class="topbar">
                <div>
                    <p class="eyebrow">Authorized Continuous Security Workspace</p>
                    <h1>@yield('page-title', 'Security Test Center')</h1>
                </div>
                <a href="{{ route('sessions.create') }}" class="btn btn-primary">+ New Assessment</a>
            </header>
        @endauth

        @if(session('success'))
            <div class="alert success">{{ session('success') }}</div>
        @endif

        @if($errors->any())
            <div class="alert danger">
                <strong>Ada yang perlu diperbaiki:</strong>
                <ul>
                    @foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach
                </ul>
            </div>
        @endif

        @yield('content')
    </main>
</div>
@yield('scripts')
</body>
</html>
