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
                <p class="muted">Pilih modul sesuai kebutuhan. Semua active checks tetap dibatasi dan hanya berjalan pada target yang sudah diverifikasi.</p>
            </div>
        </div>

        <input type="hidden" name="profile" id="profile-input" value="{{ old('profile', 'balanced') }}">
        <div class="profile-grid">
            <button type="button" class="profile-card" data-profile="quick"><strong>Quick</strong><span>Transport + browser security baseline.</span></button>
            <button type="button" class="profile-card active" data-profile="balanced"><strong>Balanced</strong><span>Recommended security coverage termasuk sensitive file exposure.</span></button>
            <button type="button" class="profile-card" data-profile="deep"><strong>Deep Safe</strong><span>Semua modul termasuk controlled resilience.</span></button>
        </div>

        <div class="module-grid" id="module-grid">
            @foreach($moduleOptions as $key => [$title, $description])
                <label class="module-card">
                    <input type="checkbox" name="modules[]" value="{{ $key }}" data-module="{{ $key }}"
                        @checked(in_array($key, old('modules', ['headers','tls','cookies','cors','exposure','rate_limit','latency','security_txt','http_methods','dns_posture','sensitive_files']), true))>
                    <span><strong>{{ $title }}</strong><small>{{ $description }}</small></span>
                </label>
            @endforeach
        </div>

        <div class="risk-callout">
            <strong>Sensitive File Exposure Scanner</strong>
            <p>Modul ini memeriksa file yang seharusnya tidak dapat dibaca publik, misalnya <code>.env</code>, <code>.git/config</code>, Laravel log, SQLite database, backup SQL/ZIP, <code>.npmrc</code>, Composer <code>auth.json</code>, dan <code>phpinfo.php</code>.</p>
            <p><b>Privasi:</b> scanner hanya membaca sampel kecil untuk mengonfirmasi signature file dan <b>tidak menyimpan isi secret</b> ke database/report. Evidence hanya berisi path, HTTP status, tipe signature, dan status redaction.</p>
        </div>
    </section>

    <section class="panel">
        <div class="panel-head">
            <div>
                <p class="eyebrow">Step 3</p>
                <h2>Auto Monitoring</h2>
                <p class="muted">Default OFF. Aktifkan hanya jika Anda ingin sistem menjalankan assessment otomatis secara berkala. Pengaturan ini dapat diubah atau dimatikan lagi dari halaman session.</p>
            </div>
        </div>

        <label class="monitoring-switch">
            <input type="checkbox" name="monitoring_enabled" value="1" id="monitoring-enabled" @checked(old('monitoring_enabled'))>
            <span>
                <strong>Enable Auto Monitoring</strong>
                <small>System akan memverifikasi ulang ownership sebelum setiap run. Jika verifikasi gagal, run tidak dijalankan.</small>
            </span>
        </label>

        <div id="monitoring-config" class="monitoring-config {{ old('monitoring_enabled') ? '' : 'disabled-box' }}">
            <div class="form-grid two">
                <label>
                    <span>Run Every</span>
                    <input type="number" min="1" max="8760" name="monitoring_interval_value" value="{{ old('monitoring_interval_value', 24) }}">
                </label>
                <label>
                    <span>Interval Unit</span>
                    <select name="monitoring_interval_unit">
                        <option value="hours" @selected(old('monitoring_interval_unit', 'hours') === 'hours')>Hour(s)</option>
                        <option value="days" @selected(old('monitoring_interval_unit') === 'days')>Day(s)</option>
                        <option value="weeks" @selected(old('monitoring_interval_unit') === 'weeks')>Week(s)</option>
                    </select>
                </label>
            </div>
            <small>Minimal 1 jam, maksimal 1 tahun. Contoh: 6 hours, 1 day, 3 days, 1 week, atau 4 weeks.</small>
        </div>

        <div class="form-grid two advanced-gap">
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
        balanced: ['headers','tls','cookies','cors','exposure','rate_limit','latency','security_txt','http_methods','dns_posture','sensitive_files'],
        deep: ['headers','tls','cookies','cors','exposure','rate_limit','latency','security_txt','http_methods','dns_posture','sensitive_files','load_resilience'],
    };

    const profileInput = document.getElementById('profile-input');
    const buttons = [...document.querySelectorAll('[data-profile]')];
    const modules = [...document.querySelectorAll('[data-module]')];
    const loadBox = document.getElementById('load-config');
    const monitoringEnabled = document.getElementById('monitoring-enabled');
    const monitoringConfig = document.getElementById('monitoring-config');

    function updateLoadBox() {
        const load = document.querySelector('[data-module="load_resilience"]');
        loadBox.classList.toggle('disabled-box', !load?.checked);
    }

    function updateMonitoringBox() {
        monitoringConfig.classList.toggle('disabled-box', !monitoringEnabled.checked);
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
    monitoringEnabled.addEventListener('change', updateMonitoringBox);

    updateLoadBox();
    updateMonitoringBox();
})();
</script>
@endsection
