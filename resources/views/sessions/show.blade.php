@extends('layouts.app')

@section('title', $session->name)
@section('page-title', $session->name)

@section('content')
<section class="session-hero">
    <div>
        <div class="hero-badges">
            <span class="pill">{{ ucfirst($session->environment) }}</span>
            <span class="status {{ $session->status }}" id="status-badge">{{ ucfirst($session->status) }}</span>
            @if($session->verified_at)<span class="status completed">Verified</span>@else<span class="status draft">Unverified</span>@endif
        </div>
        <h2>{{ $session->target_url }}</h2>
        <p>{{ count($session->selected_modules ?? []) }} security modules • Profile {{ ucfirst($session->profile) }}</p>
    </div>
    <div class="score-ring">
        <span>Score</span>
        <strong id="score-value">{{ $session->score ?? '—' }}</strong>
    </div>
</section>

@if(!$session->verified_at)
<section class="panel verification-panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">Ownership Verification</p>
            <h2>Verifikasi target sebelum audit</h2>
            <p class="muted">Ini mencegah controlled load digunakan terhadap sistem yang bukan milik Anda.</p>
        </div>
    </div>

    <div class="verification-steps">
        <div><span>1</span><p>Buat file berikut pada aplikasi target:</p></div>
        <code>{{ rtrim($session->target_url, '/') }}{{ config('security_test.verification_path') }}</code>
        <div><span>2</span><p>Isi file harus persis satu baris berikut:</p></div>
        <code>{{ $session->verification_token }}</code>
    </div>

    <form method="POST" action="{{ route('sessions.verify', $session) }}">
        @csrf
        <button class="btn btn-primary" type="submit">Verify Target Now</button>
    </form>
</section>
@else
<section class="run-grid">
    <article class="panel progress-panel">
        <div class="panel-head">
            <div>
                <p class="eyebrow">Audit Engine</p>
                <h2 id="stage-name">{{ $session->current_stage ?: 'Ready to run' }}</h2>
            </div>
            <strong id="progress-text">{{ $session->progress }}%</strong>
        </div>

        <div class="progress-track"><div id="progress-bar" style="width: {{ $session->progress }}%"></div></div>

        <div class="module-tags">
            @foreach($session->selected_modules ?? [] as $module)<span>{{ str_replace('_', ' ', $module) }}</span>@endforeach
        </div>

        @if($session->error_message)
            <div class="alert danger">{{ $session->error_message }}</div>
        @endif

        <form method="POST" action="{{ route('sessions.run', $session) }}">
            @csrf
            <button class="btn btn-primary" type="submit" @disabled(in_array($session->status, ['queued','running'], true))>
                {{ $session->status === 'completed' ? 'Run Audit Again' : 'Start Security Audit' }}
            </button>
        </form>
    </article>

    <article class="panel terminal-panel">
        <div class="panel-head"><div><p class="eyebrow">Live Engine</p><h2>Execution Log</h2></div></div>
        <div class="terminal" id="live-terminal">
            @forelse($session->logs->reverse() as $log)
                <div><span>[{{ optional($log->created_at)->format('H:i:s') }}]</span> {{ $log->message }}</div>
            @empty
                <div><span>[idle]</span> waiting for audit...</div>
            @endforelse
        </div>
    </article>
</section>
@endif

@if($session->status === 'completed')
@php
    $counts = [
        'critical' => $session->findings->where('severity','critical')->count(),
        'high' => $session->findings->where('severity','high')->count(),
        'medium' => $session->findings->where('severity','medium')->count(),
        'low' => $session->findings->where('severity','low')->count(),
        'info' => $session->findings->where('severity','info')->count(),
    ];
@endphp

<section class="metrics">
    @foreach(['critical','high','medium','low'] as $severity)
    <article class="metric-card">
        <span>{{ ucfirst($severity) }}</span>
        <strong>{{ $counts[$severity] }}</strong>
        <small>Security findings</small>
    </article>
    @endforeach
</section>

<section class="panel">
    <div class="panel-head">
        <div><p class="eyebrow">Assessment Report</p><h2>Findings & Remediation</h2></div>
        <a class="btn btn-secondary" href="{{ route('sessions.report', $session) }}">Export JSON</a>
    </div>

    <div class="finding-list">
        @forelse($session->findings as $finding)
        <article class="finding">
            <div class="finding-top">
                <span class="severity {{ $finding->severity }}">{{ strtoupper($finding->severity) }}</span>
                <span class="pill">{{ str_replace('_', ' ', $finding->module) }}</span>
            </div>
            <h3>{{ $finding->title }}</h3>
            <p>{{ $finding->description }}</p>
            @if($finding->evidence)
                <div class="evidence"><strong>Evidence</strong><code>{{ $finding->evidence }}</code></div>
            @endif
            <div class="remediation"><strong>Recommended Remediation</strong><p>{{ $finding->remediation }}</p></div>
        </article>
        @empty
            <div class="empty">Tidak ada finding.</div>
        @endforelse
    </div>
</section>
@endif
@endsection

@section('scripts')
@if(in_array($session->status, ['queued','running'], true))
<script>
(() => {
    const statusUrl = @json(route('sessions.status', $session));
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const stage = document.getElementById('stage-name');
    const badge = document.getElementById('status-badge');
    const terminal = document.getElementById('live-terminal');

    let stopped = false;

    async function poll() {
        if (stopped) return;

        try {
            const response = await fetch(statusUrl, {headers: {'Accept': 'application/json'}});
            if (!response.ok) return;
            const data = await response.json();

            progressBar.style.width = `${Math.max(0, Math.min(100, data.progress || 0))}%`;
            progressText.textContent = `${data.progress || 0}%`;
            stage.textContent = data.stage || data.status;
            badge.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
            badge.className = `status ${data.status}`;

            if (Array.isArray(data.logs) && data.logs.length) {
                terminal.innerHTML = data.logs.map(log => `<div><span>[${new Date(log.created_at).toLocaleTimeString()}]</span> ${escapeHtml(log.message)}</div>`).join('');
                terminal.scrollTop = terminal.scrollHeight;
            }

            if (data.status === 'completed' || data.status === 'failed') {
                stopped = true;
                window.location.reload();
            }
        } catch (_) {
            // keep polling; temporary network failure should not stop the UI
        }
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]));
    }

    poll();
    const timer = setInterval(() => {
        if (stopped) {
            clearInterval(timer);
            return;
        }
        poll();
    }, 1200);
})();
</script>
@endif
@endsection
