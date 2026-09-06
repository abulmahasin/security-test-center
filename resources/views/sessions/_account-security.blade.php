<section class="panel account-security-panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">Account Compromise Defense</p>
            <h2>Account Security Lab</h2>
            <p class="muted">Validasi jalur yang biasanya dipakai sebelum account takeover: account enumeration, automation resistance, login surface, dan password recovery. Active probes hanya memakai dedicated test identity; passive checks GET-only.</p>
        </div>
        <span class="pill">{{ $session->accountTests->count() }} bounded tests</span>
    </div>

    @if(!in_array('account_compromise', $session->selected_modules ?? [], true))
        <div class="risk-callout">
            <strong>Account Compromise Defense belum aktif pada module session</strong>
            <p>Anda tetap dapat menyiapkan test case, tetapi test akan dijalankan oleh audit hanya jika module <code>account_compromise</code> dipilih.</p>
        </div>
    @endif

    <div class="auth-config-grid">
        <div class="auth-config-card">
            <h3>Create Account Defense Test</h3>
            <p class="muted">Gunakan identity Form Login khusus testing. Jangan gunakan akun pegawai/siswa/admin produksi milik orang nyata.</p>

            @if($session->identities->where('auth_type', 'form')->isEmpty())
                <div class="empty">Belum ada Form Login test identity. Tambahkan terlebih dahulu pada Test Identity Vault di atas.</div>
            @else
                <form method="POST" action="{{ route('sessions.account-tests.store', $session) }}" class="auth-form">
                    @csrf
                    <div class="form-grid two">
                        <label>
                            <span>Dedicated Test Identity</span>
                            <select name="security_identity_id" required>
                                @foreach($session->identities->where('auth_type', 'form') as $identity)
                                    <option value="{{ $identity->id }}">{{ $identity->label }} @if($identity->expected_role)({{ $identity->expected_role }})@endif</option>
                                @endforeach
                            </select>
                        </label>
                        <label>
                            <span>Test Type</span>
                            <select name="kind" id="account-test-kind" required>
                                <option value="login_enumeration">Login Enumeration Differential</option>
                                <option value="login_throttling">Login Throttling / Lockout Signal</option>
                                <option value="login_surface">Login Surface — GET only</option>
                                <option value="password_reset_surface">Password Recovery Surface — GET only</option>
                            </select>
                        </label>
                    </div>
                    <label class="field-block">
                        <span>Test Label</span>
                        <input name="label" placeholder="Student Account Takeover Resistance" required>
                    </label>
                    <label class="field-block" id="account-test-path-wrap">
                        <span>Recovery Path (only for Password Recovery Surface)</span>
                        <input name="path" value="/forgot-password" placeholder="/forgot-password">
                        <small>Scanner hanya melakukan GET pada path ini. Tidak mengirim reset email, OTP, atau token.</small>
                    </label>

                    <div class="secret-warning">
                        <strong>Hard safety policy</strong>
                        <p><b>Enumeration:</b> satu invalid attempt ke akun uji + satu ke username sintetis. <b>Throttling:</b> maksimal tiga invalid attempts. <b>Surface checks:</b> GET-only tanpa side effect. Tidak ada dictionary, spraying, credential stuffing, phishing, atau password extraction.</p>
                    </div>

                    <label class="monitoring-switch">
                        <input type="checkbox" name="dedicated_test_account_confirmed" value="1" required>
                        <span><strong>Saya mengonfirmasi ini dedicated test account</strong><small>Akun ini memang dibuat/dipilih khusus untuk security testing dan bukan akun user produksi.</small></span>
                    </label>

                    <button class="btn btn-secondary" type="submit">Add Account Security Test</button>
                </form>
            @endif
        </div>

        <div class="auth-config-card">
            <h3>What This Proves</h3>
            <div class="security-explain-list">
                <div><strong>Account Enumeration</strong><p>Menilai apakah respons login membocorkan perbedaan antara username yang terdaftar dan yang tidak ada. Ini sering menjadi langkah awal sebelum phishing atau credential stuffing.</p></div>
                <div><strong>Login Automation Resistance</strong><p>Menilai apakah ada sinyal 429, Retry-After, rate-limit depletion, atau perubahan denial dalam maksimum tiga invalid attempts.</p></div>
                <div><strong>Login / Recovery Hygiene</strong><p>Memeriksa CSRF signal, form posture, dan metadata login/reset secara GET-only. Recovery test tidak pernah mengirim email reset atau token.</p></div>
                <div><strong>Authenticated Takeover Impact</strong><p>Jika attacker sudah memiliki credential/session, dampaknya diuji oleh Privilege Boundary + IDOR/BOLA module menggunakan akun uji terenkripsi.</p></div>
            </div>
        </div>
    </div>

    <div class="auth-matrix">
        <div class="panel-head compact"><div><p class="eyebrow">Configured Defenses</p><h3>Account Security Tests</h3></div></div>
        @forelse($session->accountTests as $test)
            @php
                $kindLabel = match($test->kind) {
                    'login_enumeration' => 'ENUMERATION',
                    'login_throttling' => 'THROTTLING',
                    'login_surface' => 'LOGIN SURFACE',
                    'password_reset_surface' => 'RECOVERY',
                    default => strtoupper($test->kind),
                };
            @endphp
            <article class="boundary-row account-test-row">
                <div>
                    <span class="change {{ in_array($test->kind, ['login_surface','password_reset_surface'], true) ? 'resolved' : ($test->kind === 'login_enumeration' ? 'new' : 'persistent') }}">{{ $kindLabel }}</span>
                    <strong>{{ $test->label }}</strong>
                    <code>{{ $test->identity?->label ?? 'Identity removed' }} @if($test->path) · {{ $test->path }} @endif</code>
                </div>
                <form method="POST" action="{{ route('account-tests.destroy', $test) }}">
                    @csrf
                    @method('DELETE')
                    <button class="btn btn-ghost btn-small" type="submit">Remove</button>
                </form>
            </article>
        @empty
            <div class="empty">Belum ada account-security test.</div>
        @endforelse
    </div>
</section>

<script>
document.addEventListener('DOMContentLoaded', () => {
    const kind = document.getElementById('account-test-kind');
    const pathWrap = document.getElementById('account-test-path-wrap');
    if (!kind || !pathWrap) return;

    const sync = () => pathWrap.classList.toggle('disabled-box', kind.value !== 'password_reset_surface');
    kind.addEventListener('change', sync);
    sync();
});
</script>
