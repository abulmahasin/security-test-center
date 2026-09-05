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
            @if($session->schedule_frequency)<span class="pill">{{ ucfirst($session->schedule_frequency) }} monitoring</span>@endif
        </div>
        <h2>{{ $session->target_url }}</h2>
        <p>{{ count($session->selected_modules ?? []) }} security modules • Profile {{ ucfirst($session->profile) }} @if($session->next_run_at) • Next {{ $session->next_run_at->format('d M Y H:i') }} @endif</p>
    </div>
    <div class="hero-score-group">
        <div class="score-ring"><span>Score</span><strong id="score-value">{{ $session->score ?? '—' }}</strong></div>
        <div class="grade-box"><span>Grade</span><strong>{{ $session->grade ?? '—' }}</strong></div>
    </div>
</section>

@if(!$session->verified_at)
<section class="panel verification-panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">Ownership Verification</p>
            <h2>Verifikasi target sebelum audit</h2>
            <p class="muted">Proof-of-control juga diverifikasi ulang sebelum setiap scheduled run.</p>
        </div>
    </div>
    <div class="verification-steps">
        <div><span>1</span><p>Buat file berikut pada aplikasi target:</p></div>
        <code>{{ rtrim($session->target_url, '/') }}{{ config('security_test.verification_path') }}</code>
        <div><span>2</span><p>Isi file harus persis satu baris berikut:</p></div>
        <code>{{ $session->verification_token }}</code>
    </div>
    <form method="POST" action="{{ route('sessions.verify', $session) }}">@csrf<button class="btn btn-primary" type="submit">Verify Target Now</button></form>
</section>
@else
<section class="run-grid">
    <article class="panel progress-panel">
        <div class="panel-head">
            <div><p class="eyebrow">Audit Engine</p><h2 id="stage-name">{{ $session->current_stage ?: 'Ready to run' }}</h2></div>
            <strong id="progress-text">{{ $session->progress }}%</strong>
        </div>
        <div class="progress-track"><div id="progress-bar" style="width: {{ $session->progress }}%"></div></div>
        <div class="module-tags">@foreach($session->selected_modules ?? [] as $module)<span>{{ str_replace('_', ' ', $module) }}</span>@endforeach</div>
        @if($session->error_message)<div class="alert danger">{{ $session->error_message }}</div>@endif
        <form method="POST" action="{{ route('sessions.run', $session) }}">@csrf
            <button class="btn btn-primary" type="submit" @disabled(in_array($session->status, ['queued','running'], true))>{{ $session->status === 'completed' ? 'Run New Assessment' : 'Start Security Audit' }}</button>
        </form>
    </article>

    <article class="panel terminal-panel">
        <div class="panel-head"><div><p class="eyebrow">Live Engine</p><h2>Execution Log</h2></div></div>
        <div class="terminal" id="live-terminal">
            @forelse($session->logs->reverse() as $log)<div><span>[{{ optional($log->created_at)->format('H:i:s') }}]</span> {{ $log->message }}</div>@empty<div><span>[idle]</span> waiting for audit...</div>@endforelse
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

<section class="metrics posture-metrics">
    <article class="metric-card"><span>Compliance</span><strong>{{ $session->compliance_score ?? '—' }}@if($session->compliance_score !== null)<small class="metric-suffix">%</small>@endif</strong><small>Selected controls without high-risk failure</small></article>
    <article class="metric-card"><span>Score Delta</span><strong class="{{ ($session->risk_delta ?? 0) < 0 ? 'text-danger' : 'text-good' }}">{{ $session->risk_delta === null ? '—' : (($session->risk_delta > 0 ? '+' : '').$session->risk_delta) }}</strong><small>@if($session->baseline)vs baseline #{{ $session->baseline->id }} ({{ $session->baseline->score }})@elseFirst baseline@endif</small></article>
    <article class="metric-card"><span>New Findings</span><strong>{{ $session->new_findings_count }}</strong><small>Non-info findings not seen in baseline</small></article>
    <article class="metric-card"><span>Resolved</span><strong class="text-good">{{ $session->resolved_findings_count }}</strong><small>Baseline fingerprints no longer detected</small></article>
</section>

<section class="metrics">
    @foreach(['critical','high','medium','low'] as $severity)
    <article class="metric-card"><span>{{ ucfirst($severity) }}</span><strong>{{ $counts[$severity] }}</strong><small>Security findings</small></article>
    @endforeach
</section>

<section class="panel">
    <div class="panel-head">
        <div><p class="eyebrow">Continuous Posture Report</p><h2>Findings & Remediation</h2><p class="muted">NEW = baru dibanding baseline. PERSISTENT = masih ditemukan sejak baseline sebelumnya.</p></div>
        <a class="btn btn-secondary" href="{{ route('sessions.report', $session) }}">Export JSON</a>
    </div>

    <div class="finding-list">
        @forelse($session->findings as $finding)
        <article class="finding {{ $finding->change_type === 'new' && $finding->severity !== 'info' ? 'finding-new' : '' }}">
            <div class="finding-top">
                <span class="severity {{ $finding->severity }}">{{ strtoupper($finding->severity) }}</span>
                <span class="pill">{{ str_replace('_', ' ', $finding->module) }}</span>
                <span class="change {{ $finding->change_type }}">{{ strtoupper($finding->change_type) }}</span>
            </div>
            <h3>{{ $finding->title }}</h3>
            <p>{{ $finding->description }}</p>
            @if($finding->evidence)<div class="evidence"><strong>Evidence</strong><code>{{ $finding->evidence }}</code></div>@endif
            <div class="remediation"><strong>Recommended Remediation</strong><p>{{ $finding->remediation }}</p></div>
        </article>
        @empty<div class="empty">Tidak ada finding.</div>@endforelse
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
            if (data.status === 'completed' || data.status === 'failed') { stopped = true; window.location.reload(); }
        } catch (_) {}
    }

    function escapeHtml(value) { return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch])); }
    poll();
    const timer = setInterval(() => { if (stopped) { clearInterval(timer); return; } poll(); }, 1200);
})();
</script>
@endif
@endsection
