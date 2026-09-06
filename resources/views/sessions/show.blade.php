@extends('layouts.app')

@section('title', $session->name)
@section('page-title', $session->name)

@section('content')
@php
    $intervalValue = 24;
    $intervalUnit = 'hours';
    if ($session->schedule_interval_minutes) {
        if ($session->schedule_interval_minutes % 10080 === 0) {
            $intervalValue = (int) ($session->schedule_interval_minutes / 10080);
            $intervalUnit = 'weeks';
        } elseif ($session->schedule_interval_minutes % 1440 === 0) {
            $intervalValue = (int) ($session->schedule_interval_minutes / 1440);
            $intervalUnit = 'days';
        } else {
            $intervalValue = max(1, (int) ($session->schedule_interval_minutes / 60));
            $intervalUnit = 'hours';
        }
    }
@endphp

<section class="session-hero">
    <div>
        <div class="hero-badges">
            <span class="pill">{{ ucfirst($session->environment) }}</span>
            <span class="status {{ $session->status }}" id="status-badge">{{ ucfirst($session->status) }}</span>
            @if($session->verified_at)<span class="status completed">Verified</span>@else<span class="status draft">Unverified</span>@endif
            @if($session->monitoring_enabled)<span class="status completed">Monitoring ON</span>@else<span class="pill">Monitoring OFF</span>@endif
        </div>
        <h2>{{ $session->target_url }}</h2>
        <p>{{ count($session->selected_modules ?? []) }} security modules • Profile {{ ucfirst($session->profile) }} @if($session->monitoring_enabled) • {{ $session->monitoringLabel() }} @endif @if($session->next_run_at) • Next {{ $session->next_run_at->format('d M Y H:i') }} @endif</p>
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
            <p class="muted">Proof-of-control wajib sebelum active audit maupun auto monitoring. Ini mencegah scanner digunakan pada sistem yang tidak Anda kuasai.</p>
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
<section class="panel monitoring-panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">User Controlled Automation</p>
            <h2>Auto Monitoring</h2>
            <p class="muted">Monitoring tidak wajib. Anda bebas mengaktifkan, mengubah interval, atau mematikannya kapan saja. Setiap auto-run tetap melakukan proof-of-control ulang.</p>
        </div>
        <span class="status {{ $session->monitoring_enabled ? 'completed' : 'draft' }}">{{ $session->monitoring_enabled ? 'ACTIVE' : 'OFF' }}</span>
    </div>

    <form method="POST" action="{{ route('sessions.monitoring', $session) }}" class="monitoring-form">
        @csrf
        @method('PATCH')
        <label class="monitoring-switch">
            <input type="checkbox" name="monitoring_enabled" value="1" id="session-monitoring-enabled" @checked($session->monitoring_enabled)>
            <span><strong>Enable Auto Monitoring</strong><small>Uncheck lalu Save untuk mematikan monitoring sepenuhnya.</small></span>
        </label>
        <div class="form-grid three monitoring-inline">
            <label><span>Run Every</span><input type="number" min="1" max="8760" name="monitoring_interval_value" value="{{ $intervalValue }}"></label>
            <label><span>Unit</span><select name="monitoring_interval_unit"><option value="hours" @selected($intervalUnit === 'hours')>Hour(s)</option><option value="days" @selected($intervalUnit === 'days')>Day(s)</option><option value="weeks" @selected($intervalUnit === 'weeks')>Week(s)</option></select></label>
            <div class="monitoring-save"><button type="submit" class="btn btn-secondary">Save Monitoring</button></div>
        </div>
        <small class="muted">Minimal 1 jam, maksimal 1 tahun. @if($session->next_run_at)Next automatic assessment: {{ $session->next_run_at->format('d M Y H:i') }}.@endif</small>
    </form>
</section>

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
        <div><p class="eyebrow">Continuous Posture Report</p><h2>Risk, Evidence & Solution</h2><p class="muted">Setiap finding menjelaskan dampak praktis dan solusi. Untuk sensitive-file scan, isi file rahasia tidak pernah disimpan di report.</p></div>
        <a class="btn btn-secondary" href="{{ route('sessions.report', $session) }}">Export JSON</a>
    </div>

    <div class="finding-list">
        @forelse($session->findings as $finding)
        <article class="finding {{ $finding->change_type === 'new' && $finding->severity !== 'info' ? 'finding-new' : '' }}">
            <div class="finding-top">
                <span class="severity {{ $finding->severity }}">{{ strtoupper($finding->severity) }}</span>
                <span class="pill">{{ str_replace('_', ' ', $finding->module) }}</span>
                <span class="change {{ $finding->change_type }}">{{ strtoupper($finding->change_type) }}</span>
                <span class="pill">{{ str_replace('_', ' ', strtoupper($finding->status)) }}</span>
            </div>
            <h3>{{ $finding->title }}</h3>
            <div class="risk-detail"><strong>Risiko / Dampak</strong><p>{{ $finding->description }}</p></div>
            @if($finding->evidence)<div class="evidence"><strong>Evidence (redacted)</strong><code>{{ $finding->evidence }}</code></div>@endif
            <div class="remediation"><strong>Solusi / Recommended Remediation</strong><p>{{ $finding->remediation }}</p></div>
            <form method="POST" action="{{ route('findings.status', $finding) }}" class="finding-governance">
                @csrf
                @method('PATCH')
                <label>
                    <span>Risk Governance</span>
                    <select name="status">
                        @foreach(['open' => 'Open', 'acknowledged' => 'Acknowledged', 'accepted_risk' => 'Accepted Risk', 'resolved' => 'Resolved', 'false_positive' => 'False Positive'] as $value => $label)
                            <option value="{{ $value }}" @selected($finding->status === $value)>{{ $label }}</option>
                        @endforeach
                    </select>
                </label>
                <button type="submit" class="btn btn-ghost">Update Status</button>
            </form>
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
