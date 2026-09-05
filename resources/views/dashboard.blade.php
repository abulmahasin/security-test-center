@extends('layouts.app')

@section('title', 'Dashboard')
@section('page-title', 'Security Operations Dashboard')

@section('content')
<section class="metrics">
    <article class="metric-card"><span>Managed Targets</span><strong>{{ $stats['targets'] }}</strong><small>Unique application URLs</small></article>
    <article class="metric-card"><span>Total Assessments</span><strong>{{ $stats['sessions'] }}</strong><small>Manual + scheduled sessions</small></article>
    <article class="metric-card"><span>Average Score</span><strong>{{ $stats['average_score'] ?? '—' }}</strong><small>Last {{ $trend->count() }} completed audits</small></article>
    <article class="metric-card"><span>Latest Posture</span><strong>{{ $stats['latest_grade'] ?? '—' }}</strong><small>Score {{ $stats['latest_score'] ?? '—' }} • Compliance {{ $stats['latest_compliance'] ?? '—' }}%</small></article>
    <article class="metric-card"><span>Continuous Monitoring</span><strong>{{ $stats['scheduled'] }}</strong><small>Scheduled security templates</small></article>
    <article class="metric-card"><span>High Risk Open</span><strong>{{ $stats['open_high'] }}</strong><small>Critical + high findings in history</small></article>
    <article class="metric-card"><span>Regressions</span><strong class="{{ $stats['regressions'] > 0 ? 'text-danger' : 'text-good' }}">{{ $stats['regressions'] }}</strong><small>Runs with score below baseline</small></article>
    <article class="metric-card"><span>Resolved Findings</span><strong class="text-good">{{ $stats['resolved_findings'] }}</strong><small>{{ $stats['new_findings'] }} new findings observed</small></article>
</section>

<div class="dashboard-grid">
    <section class="panel">
        <div class="panel-head">
            <div><p class="eyebrow">Continuous Posture</p><h2>Score & Compliance Trend</h2><p class="muted">Audit history is retained so deterioration becomes visible instead of silently replacing the previous report.</p></div>
        </div>
        <div class="trend-list">
            @forelse($trend as $point)
                <div class="trend-row">
                    <div class="trend-label"><strong>{{ $point['completed_at'] }}</strong><span>{{ Str::limit($point['name'], 30) }}</span></div>
                    <div class="trend-bars">
                        <div class="trend-line"><span>Score</span><div><i style="width: {{ $point['score'] }}%"></i></div><strong>{{ $point['score'] }}</strong></div>
                        <div class="trend-line compliance"><span>Compliance</span><div><i style="width: {{ $point['compliance'] ?? 0 }}%"></i></div><strong>{{ $point['compliance'] ?? '—' }}</strong></div>
                    </div>
                </div>
            @empty
                <div class="empty">Belum ada completed assessment untuk membentuk trend.</div>
            @endforelse
        </div>
    </section>

    <section class="panel">
        <div class="panel-head"><div><p class="eyebrow">Automation</p><h2>Upcoming Security Runs</h2></div></div>
        <div class="upcoming-list">
            @forelse($upcoming as $item)
                <a href="{{ route('sessions.show', $item) }}" class="upcoming-item">
                    <div><strong>{{ $item->name }}</strong><span>{{ $item->target_url }}</span></div>
                    <div class="upcoming-time"><span>{{ ucfirst($item->schedule_frequency) }}</span><strong>{{ $item->next_run_at->format('d M H:i') }}</strong></div>
                </a>
            @empty
                <div class="empty">Belum ada continuous monitoring. Atur schedule saat membuat session.</div>
            @endforelse
        </div>
    </section>
</div>

<section class="panel">
    <div class="panel-head">
        <div><p class="eyebrow">Assessment History</p><h2>Security Sessions</h2></div>
        <a class="btn btn-secondary" href="{{ route('sessions.create') }}">Create Session</a>
    </div>

    <div class="table-wrap">
        <table>
            <thead><tr><th>Session</th><th>Status</th><th>Posture</th><th>Compliance</th><th>Delta</th><th>Changes</th><th>Created</th></tr></thead>
            <tbody>
            @forelse($sessions as $session)
                <tr>
                    <td><a class="row-title" href="{{ route('sessions.show', $session) }}">{{ $session->name }}</a><small>{{ $session->target_url }}</small></td>
                    <td><span class="status {{ $session->status }}">{{ ucfirst($session->status) }}</span></td>
                    <td><strong>{{ $session->grade ?? '—' }}</strong> <small class="inline-small">{{ $session->score ?? '—' }}/100</small></td>
                    <td>{{ $session->compliance_score !== null ? $session->compliance_score.'%' : '—' }}</td>
                    <td class="{{ ($session->risk_delta ?? 0) < 0 ? 'text-danger' : (($session->risk_delta ?? 0) > 0 ? 'text-good' : '') }}">{{ $session->risk_delta === null ? '—' : (($session->risk_delta > 0 ? '+' : '').$session->risk_delta) }}</td>
                    <td><span class="change new">+{{ $session->new_findings_count }}</span> <span class="change resolved">-{{ $session->resolved_findings_count }}</span></td>
                    <td>{{ $session->created_at->format('d M Y H:i') }}</td>
                </tr>
            @empty
                <tr><td colspan="7" class="empty">Belum ada security session.</td></tr>
            @endforelse
            </tbody>
        </table>
    </div>
</section>
@endsection
