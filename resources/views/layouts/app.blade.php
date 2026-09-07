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
            <div class="sidebar-main">
                <a href="{{ route('dashboard') }}" class="brand">
                    <span class="brand-mark">ST</span>
                    <span class="brand-copy">
                        <strong>Security Test Center</strong>
                        <small>Application security workspace</small>
                    </span>
                </a>

                <div class="nav-section">
                    <span class="nav-label">Workspace</span>
                    <nav>
                        <a href="{{ route('dashboard') }}" class="{{ request()->routeIs('dashboard') ? 'active' : '' }}">
                            <span class="nav-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24"><path d="M4 13h6V4H4v9Zm0 7h6v-5H4v5Zm10 0h6v-9h-6v9Zm0-16v5h6V4h-6Z"/></svg>
                            </span>
                            <span>Overview</span>
                        </a>
                        <a href="{{ route('sessions.create') }}" class="{{ request()->routeIs('sessions.create') ? 'active' : '' }}">
                            <span class="nav-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>
                            </span>
                            <span>New assessment</span>
                        </a>
                    </nav>
                </div>
            </div>

            <div class="sidebar-bottom">
                <div class="userbox">
                    <span class="avatar">{{ strtoupper(substr(auth()->user()->name, 0, 1)) }}</span>
                    <div>
                        <strong>{{ auth()->user()->name }}</strong>
                        <span>{{ auth()->user()->email }}</span>
                    </div>
                </div>
                <form method="POST" action="{{ route('logout') }}">
                    @csrf
                    <button class="btn btn-ghost btn-block" type="submit">Sign out</button>
                </form>
            </div>
        </aside>
    @endauth

    <main class="{{ auth()->check() ? 'content' : 'content-auth' }}">
        @auth
            <header class="topbar">
                <div class="topbar-copy">
                    <p class="eyebrow">Security workspace</p>
                    <h1>@yield('page-title', 'Security Test Center')</h1>
                    @hasSection('page-description')
                        <p class="page-description">@yield('page-description')</p>
                    @endif
                </div>
                @unless(request()->routeIs('sessions.create'))
                    <a href="{{ route('sessions.create') }}" class="btn btn-primary">
                        <span class="btn-plus">+</span>
                        New assessment
                    </a>
                @endunless
            </header>
        @endauth

        @if(session('success'))
            <div class="alert success">{{ session('success') }}</div>
        @endif

        @if($errors->any())
            <div class="alert danger">
                <strong>Ada yang perlu diperbaiki:</strong>
                <ul>
                    @foreach($errors->all() as $error)
                        <li>{{ $error }}</li>
                    @endforeach
                </ul>
            </div>
        @endif

        @yield('content')
    </main>
</div>
@yield('scripts')
</body>
</html>
