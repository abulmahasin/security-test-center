@extends('layouts.app')

@section('title', 'Dashboard')
@section('page-title', 'Security Operations Dashboard')

@section('content')
<section class="metrics">
    <article class="metric-card">
        <span>Total Sessions</span>
        <strong>{{ $stats['sessions'] }}</strong>
        <small>Audit yang pernah dibuat</small>
    </article>
    <article class="metric-card">
        <span>Verified Targets</span>
        <strong>{{ $stats['verified'] }}</strong>
        <small>Target dengan proof-of-control</small>
    </article>
    <article class="metric-card">
        <span>High Risk Open</span>
        <strong>{{ $stats['open_high'] }}</strong>
        <small>Critical + high findings</small>
    </article>
    <article class="metric-card">
        <span>Latest Score</span>
        <strong>{{ $stats['latest_score'] ?? '—' }}</strong>
        <small>Skor audit terakhir selesai</small>
    </article>
</section>

<section class="panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">Recent Activity</p>
            <h2>Security Sessions</h2>
        </div>
        <a class="btn btn-secondary" href="{{ route('sessions.create') }}">Create Session</a>
    </div>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Session</th>
                    <th>Environment</th>
                    <th>Status</th>
                    <th>Score</th>
                    <th>Findings</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
            @forelse($sessions as $session)
                <tr>
                    <td>
                        <a class="row-title" href="{{ route('sessions.show', $session) }}">{{ $session->name }}</a>
                        <small>{{ $session->target_url }}</small>
                    </td>
                    <td><span class="pill">{{ ucfirst($session->environment) }}</span></td>
                    <td><span class="status {{ $session->status }}">{{ ucfirst($session->status) }}</span></td>
                    <td class="score-cell">{{ $session->score ?? '—' }}</td>
                    <td>{{ $session->findings_count }}</td>
                    <td>{{ $session->created_at->format('d M Y H:i') }}</td>
                </tr>
            @empty
                <tr><td colspan="6" class="empty">Belum ada security session.</td></tr>
            @endforelse
            </tbody>
        </table>
    </div>
</section>
@endsection
