@extends('layouts.app')

@section('title', 'New Security Test')
@section('page-title', 'Create Security Session')

@section('content')
<form method="POST" action="{{ route('sessions.store') }}" class="test-layout" id="session-form">
    @csrf

    <section class="panel">
        <div class="panel-head">
            <div>
                <p class="eyebrow">Step 1</p>
                <h2>Target Application</h2>
                <p class="muted">Target melewati SSRF guard dan proof-of-control sebelum audit atau monitoring berjalan.</p>
            </div>
        </div>

        <div class="form-grid two">
            <label>
                <span>Session Name</span>
                <input name="name" value="{{ old('name') }}" placeholder="LMS Production Security Baseline" required>
            </label>
            <label>
                <span>Environment</span>
                <select name="environment">
                    @foreach(['production', 'staging', 'development', 'local'] as $env)
                        <option value="{{ $env }}" @selected(old('environment', 'production') === $env)>{{ ucfirst($env) }}</option>
                    @endforeach
                </select>
            </label>
        </div>

        <label class="field-block">
            <span>Application URL</span>
            <input type="url" name="target_url" value="{{ old('target_url') }}" placeholder="https://app.example.com" required>
            <small>Gunakan base URL aplikasi. Private/reserved network tetap mengikuti server safety policy.</small>
        </label>
    </section>

    <section class="panel">
        <div class="panel-head">
            <div>
                <p class="eyebrow">Step 2</p>
                <h2>Security Coverage</h2>
                <p class="muted">Deep Safe menggabungkan passive posture checks dengan controlled load yang dibatasi server.</p>
            </div>
        </div>

        <input type="hidden" name="profile" id="profile-input" value="{{ old('profile', 'balanced') }}">
        <div class="profile-grid">
            <button type="button" class="profile-card" data-profile="quick"><strong>Quick</strong><span>Transport + browser security baseline.</span></button>
            <button type="button" class="profile-card active" data-profile="balanced"><strong>Balanced</strong><span>Recommended continuous security coverage.</span></button>
            <button type="button" class="profile-card" data-profile="deep"><strong>Deep Safe</strong><span>Semua modul termasuk controlled resilience.</span></button>
        </div>

        <div class="module-grid" id="module-grid">
            @foreach($moduleOptions as $key => [$title, $description])
                <label class="module-card">
                    <input type="checkbox" name="modules[]" value="{{ $key }}" data-module="{{ $key }}"
                        @checked(in_array($key, old('modules', ['headers','tls','cookies','cors','exposure','rate_limit','latency','security_txt','http_methods','dns_posture']), true))>
                    <span><strong>{{ $title }}</strong><small>{{ $description }}</small></span>
                </label>
            @endforeach
        </div>
    </section>

    <section class="panel">
        <div class="panel-head">
            <div>
                <p class="eyebrow">Step 3</p>
                <h2>Continuous Monitoring</h2>
                <p class="muted">Scheduled run akan memverifikasi ulang proof-of-control sebelum setiap scan dan membuat session baru agar history tetap utuh.</p>
            </div>
        </div>

        <div class="form-grid two">
            <label>
                <span>Audit Schedule</span>
                <select name="schedule_frequency">
                    <option value="none" @selected(old('schedule_frequency','none') === 'none')>Manual only</option>
                    <option value="daily" @selected(old('schedule_frequency') === 'daily')>Daily</option>
                    <option value="weekly" @selected(old('schedule_frequency') === 'weekly')>Weekly</option>
                    <option value="monthly" @selected(old('schedule_frequency') === 'monthly')>Monthly</option>
                </select>
                <small>Laravel scheduler harus aktif pada deployment production.</small>
            </label>
            <label>
                <span>Rate Limit Endpoint</span>
                <input name="rate_limit_path" value="{{ old('rate_limit_path', '/login') }}" placeholder="/login">
                <small>Hanya low-volume probe pada path yang Anda tentukan.</small>
            </label>
        </div>

        <div id="load-config" class="load-box">
            <div>
                <strong>DDoS Resilience Simulation — Safety Guarded</strong>
                <p>Controlled GET load untuk target terverifikasi. Nilai selalu di-clamp backend dan tidak menyediakan flood/raw packet/amplification.</p>
            </div>
            <div class="form-grid three">
                <label><span>Virtual Users</span><input type="number" min="1" name="load[vus]" value="{{ old('load.vus', 5) }}"></label>
                <label><span>Target RPS</span><input type="number" min="1" name="load[rps]" value="{{ old('load.rps', 5) }}"></label>
                <label><span>Duration (sec)</span><input type="number" min="1" name="load[duration]" value="{{ old('load.duration', 10) }}"></label>
            </div>
            <small>Server caps: {{ config('security_test.load.max_vus') }} VUs, {{ config('security_test.load.max_rps') }} RPS, {{ config('security_test.load.max_duration') }}s, maksimum {{ config('security_test.load.max_requests') }} request.</small>
        </div>
    </section>

    <div class="form-actions">
        <a href="{{ route('dashboard') }}" class="btn btn-ghost">Cancel</a>
        <button class="btn btn-primary" type="submit">Create Security Baseline</button>
    </div>
</form>
@endsection

@section('scripts')
<script>
(() => {
    const presets = {
        quick: ['headers','tls','cookies','cors','security_txt'],
        balanced: ['headers','tls','cookies','cors','exposure','rate_limit','latency','security_txt','http_methods','dns_posture'],
        deep: ['headers','tls','cookies','cors','exposure','rate_limit','latency','security_txt','http_methods','dns_posture','load_resilience'],
    };

    const profileInput = document.getElementById('profile-input');
    const buttons = [...document.querySelectorAll('[data-profile]')];
    const modules = [...document.querySelectorAll('[data-module]')];
    const loadBox = document.getElementById('load-config');

    function updateLoadBox() {
        const load = document.querySelector('[data-module="load_resilience"]');
        loadBox.classList.toggle('disabled-box', !load?.checked);
    }

    function activate(profile) {
        profileInput.value = profile;
        buttons.forEach(btn => btn.classList.toggle('active', btn.dataset.profile === profile));
        modules.forEach(input => input.checked = presets[profile].includes(input.value));
        updateLoadBox();
    }

    buttons.forEach(btn => btn.addEventListener('click', () => activate(btn.dataset.profile)));
    modules.forEach(input => input.addEventListener('change', () => {
        profileInput.value = 'custom';
        buttons.forEach(btn => btn.classList.remove('active'));
        updateLoadBox();
    }));

    updateLoadBox();
})();
</script>
@endsection
