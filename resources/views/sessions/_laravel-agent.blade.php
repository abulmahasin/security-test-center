<section class="panel laravel-agent-panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">Source-Assisted Validation</p>
            <h2>Laravel Agent Manifest</h2>
            <p class="muted">Import metadata route, middleware, dan security config dari aplikasi Laravel yang Anda kontrol. Manifest tidak berisi source code, password, APP_KEY, database content, atau environment secrets.</p>
        </div>
        <span class="pill">{{ $session->agentManifests->count() }} recent manifests</span>
    </div>

    @if(!in_array('laravel_agent', $session->selected_modules ?? [], true))
        <div class="risk-callout">
            <strong>Laravel Agent module belum aktif</strong>
            <p>Manifest tetap dapat diimport, tetapi analisis route/config hanya masuk ke audit jika module <code>laravel_agent</code> dipilih.</p>
        </div>
    @endif

    <div class="auth-config-grid">
        <div class="auth-config-card">
            <h3>Generate Manifest</h3>
            <p class="muted">Copy file <code>agent/laravel/SecurityManifestCommand.php</code> dari repository ini ke <code>app/Console/Commands/SecurityManifestCommand.php</code> pada aplikasi Laravel target.</p>
            <div class="evidence">
                <strong>Run on target application</strong>
                <code>php artisan security:manifest --output=security-manifest.json</code>
            </div>
            <div class="secret-warning">
                <strong>Data minimization</strong>
                <p>Agent hanya mengekspor method, URI, route name, controller/action, middleware, Laravel/PHP version, APP_DEBUG boolean, serta session-cookie posture. Secret values tidak diekspor.</p>
            </div>
        </div>

        <div class="auth-config-card">
            <h3>Import Manifest JSON</h3>
            <form method="POST" action="{{ route('sessions.agent-manifests.store', $session) }}" class="auth-form">
                @csrf
                <label class="field-block">
                    <span>Source Label</span>
                    <input name="source_label" placeholder="LMS Production">
                </label>
                <label class="field-block">
                    <span>Manifest JSON</span>
                    <textarea name="manifest_json" rows="11" placeholder='{"app":"LMS","framework_version":"12.x","routes":[]}' required></textarea>
                </label>
                <small class="muted">Maksimum 1 MB dan 5.000 route. Input disanitasi sebelum disimpan.</small>
                <button class="btn btn-secondary" type="submit">Import Laravel Manifest</button>
            </form>
        </div>
    </div>

    @if($session->agentManifests->isNotEmpty() && $session->identities->isNotEmpty())
        <div class="risk-callout">
            <strong>Automatic Authorization Matrix</strong>
            <p>Pilih test identity role rendah untuk membuat rule <code>DENIED</code> otomatis dari route statis/read-only yang terlihat administratif seperti <code>/admin</code>, <code>/settings</code>, <code>/users</code>, <code>/roles</code>, dan <code>/permissions</code>. Maksimum 100 rule per manifest. Route dinamis berparameter tidak ditebak otomatis.</p>
        </div>
    @endif

    <div class="auth-matrix">
        <div class="panel-head compact"><div><p class="eyebrow">Manifest History</p><h3>Source-Assisted Snapshots</h3></div></div>
        @forelse($session->agentManifests as $manifest)
            <article class="boundary-row">
                <div>
                    <span class="change resolved">LARAVEL {{ $manifest->framework_version ?: '?' }}</span>
                    <strong>{{ $manifest->source_label }}</strong>
                    <code>{{ $manifest->routes_count }} routes · {{ optional($manifest->received_at)->format('d M Y H:i') }}</code>
                </div>
                <div class="manifest-actions">
                    @if($session->identities->isNotEmpty())
                        <form method="POST" action="{{ route('sessions.agent-manifests.generate-rules', [$session, $manifest]) }}" class="manifest-rule-form">
                            @csrf
                            <select name="security_identity_id" required>
                                @foreach($session->identities as $identity)
                                    <option value="{{ $identity->id }}">{{ $identity->label }} @if($identity->expected_role)({{ $identity->expected_role }})@endif</option>
                                @endforeach
                            </select>
                            <button class="btn btn-secondary btn-small" type="submit">Generate DENIED Matrix</button>
                        </form>
                    @endif
                    <form method="POST" action="{{ route('agent-manifests.destroy', $manifest) }}">
                        @csrf
                        @method('DELETE')
                        <button class="btn btn-ghost btn-small" type="submit">Delete</button>
                    </form>
                </div>
            </article>
        @empty
            <div class="empty">Belum ada Laravel Agent manifest.</div>
        @endforelse
    </div>
</section>
