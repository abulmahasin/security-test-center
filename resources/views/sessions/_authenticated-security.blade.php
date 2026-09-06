<section class="panel auth-security-panel">
    <div class="panel-head">
        <div>
            <p class="eyebrow">Authenticated Security</p>
            <h2>Test Identity Vault & Privilege Boundaries</h2>
            <p class="muted">Gunakan akun/session uji yang Anda kontrol. Secret disimpan terenkripsi, tidak pernah ditampilkan kembali, dan tidak masuk report/log. Resource checks hanya GET read-only.</p>
        </div>
        <span class="pill">{{ $session->identities->count() }} identities · {{ $session->accessRules->count() }} rules</span>
    </div>

    @if(!in_array('authenticated_access', $session->selected_modules ?? [], true))
        <div class="risk-callout">
            <strong>Module belum aktif pada session ini</strong>
            <p>Identity dan rules dapat tetap disiapkan, tetapi scanner tidak akan menjalankannya sampai module <code>authenticated_access</code> dipilih pada assessment yang mendukungnya.</p>
        </div>
    @endif

    <div class="auth-config-grid">
        <div class="auth-config-card">
            <h3>1. Add Test Identity</h3>
            <p class="muted">Gunakan akun khusus testing. Session Cookie Replay hanya menerima cookie yang Anda paste dari dedicated test account; sistem tidak mencoba mencuri cookie dari browser atau target.</p>
            <form method="POST" action="{{ route('sessions.identities.store', $session) }}" class="auth-form">
                @csrf
                <div class="form-grid two">
                    <label><span>Identity Label</span><input name="label" placeholder="Student Test" required></label>
                    <label><span>Expected Role</span><input name="expected_role" placeholder="student"></label>
                </div>
                <div class="form-grid two">
                    <label>
                        <span>Authentication Type</span>
                        <select name="auth_type" id="auth-type-select">
                            <option value="form">Form Login</option>
                            <option value="bearer">Bearer Token</option>
                            <option value="cookie">Provided Test Session Cookie</option>
                        </select>
                    </label>
                    <label><span>Success / Verification Path</span><input name="success_path" value="/" placeholder="/dashboard"></label>
                </div>
                <div id="form-auth-fields">
                    <div class="form-grid three">
                        <label><span>Login Path</span><input name="login_path" value="/login" placeholder="/login"></label>
                        <label><span>Username Field</span><input name="username_field" value="email" placeholder="email"></label>
                        <label><span>Password Field</span><input name="password_field" value="password" placeholder="password"></label>
                    </div>
                    <div class="form-grid two">
                        <label><span>Username / Email</span><input name="username" autocomplete="off" placeholder="student-test@example.com"></label>
                        <label><span>Password</span><input type="password" name="password" autocomplete="new-password" placeholder="Test account password"></label>
                    </div>
                </div>
                <div id="bearer-auth-fields" class="disabled-box">
                    <label class="field-block"><span>Bearer Token</span><input type="password" name="bearer_token" autocomplete="new-password" placeholder="Test API token"></label>
                </div>
                <div id="cookie-auth-fields" class="disabled-box">
                    <label class="field-block"><span>Test Session Cookie Header</span><input type="password" name="session_cookie" autocomplete="new-password" placeholder="laravel_session=...; XSRF-TOKEN=..."></label>
                    <small>Paste hanya cookie dari dedicated test account yang Anda kontrol. Cookie dienkripsi at-rest dan tidak pernah ditampilkan lagi.</small>
                </div>
                <div class="secret-warning">
                    <strong>Credential handling</strong>
                    <p>Password/token/session cookie dienkripsi dengan Laravel Crypt. UI tidak menyediakan reveal secret dan report selalu menandai <code>credentials_redacted=true</code>.</p>
                </div>
                <button class="btn btn-secondary" type="submit">Add Encrypted Test Identity</button>
            </form>
        </div>

        <div class="auth-config-card">
            <h3>2. Add Security Boundary</h3>
            <p class="muted">Uji vertical privilege escalation maupun object-level access antar-user/tenant.</p>
            @if($session->identities->isEmpty())
                <div class="empty">Tambahkan test identity terlebih dahulu.</div>
            @else
                <form method="POST" action="{{ route('sessions.access-rules.store', $session) }}" class="auth-form">
                    @csrf
                    <label class="field-block">
                        <span>Test Identity</span>
                        <select name="security_identity_id" required>
                            @foreach($session->identities as $identity)
                                <option value="{{ $identity->id }}">{{ $identity->label }} @if($identity->expected_role)({{ $identity->expected_role }})@endif</option>
                            @endforeach
                        </select>
                    </label>
                    <div class="form-grid two">
                        <label><span>Rule Label</span><input name="label" placeholder="Admin User Management" required></label>
                        <label>
                            <span>Test Type</span>
                            <select name="kind">
                                <option value="authorization">Authorization / Role Boundary</option>
                                <option value="idor">IDOR / BOLA Object Boundary</option>
                            </select>
                        </label>
                    </div>
                    <label class="field-block"><span>Resource Path</span><input name="path" placeholder="/admin/users atau /api/orders/OTHER_ID" required></label>
                    <label class="field-block">
                        <span>Expected Access</span>
                        <select name="expectation">
                            <option value="denied">DENIED — identity must not read this resource</option>
                            <option value="allowed">ALLOWED — identity should read this resource</option>
                        </select>
                    </label>
                    <label class="field-block">
                        <span>Business Context</span>
                        <textarea name="business_context" rows="3" placeholder="Contoh: Student tidak boleh membuka manajemen user admin. Untuk IDOR: order 9821 dimiliki user B, sedangkan identity ini adalah user A."></textarea>
                        <small>Konteks ini dipakai report agar risiko mudah dipahami developer, auditor, dan manajemen.</small>
                    </label>
                    <div class="secret-warning">
                        <strong>How this proves a weakness</strong>
                        <p>Rule DENIED yang menerima HTTP 2xx setelah login menjadi finding <b>CRITICAL</b>. Authorization menandakan role boundary jebol; IDOR/BOLA menandakan object milik user/tenant lain bisa dibaca. Hanya GET read-only yang digunakan.</p>
                    </div>
                    <button class="btn btn-secondary" type="submit">Add Security Boundary</button>
                </form>
            @endif
        </div>
    </div>

    <div class="auth-matrix">
        <div class="panel-head compact"><div><p class="eyebrow">Authorization Matrix</p><h3>Configured Identities & Boundaries</h3></div></div>
        @forelse($session->identities as $identity)
            <article class="identity-card">
                <div class="identity-head">
                    <div>
                        <strong>{{ $identity->label }}</strong>
                        <span>{{ $identity->expected_role ?: 'Role not specified' }} · {{ strtoupper($identity->auth_type) }} · secret encrypted</span>
                    </div>
                    <form method="POST" action="{{ route('identities.destroy', $identity) }}" onsubmit="return confirm('Delete this test identity and its boundary rules?')">
                        @csrf
                        @method('DELETE')
                        <button class="btn btn-ghost btn-small" type="submit">Delete</button>
                    </form>
                </div>
                <div class="boundary-list">
                    @forelse($identity->accessRules as $rule)
                        <div class="boundary-row">
                            <div>
                                <span class="change {{ $rule->expectation === 'denied' ? 'new' : 'resolved' }}">{{ strtoupper($rule->expectation) }}</span>
                                <span class="pill">{{ $rule->kind === 'idor' ? 'IDOR/BOLA' : 'AUTHZ' }}</span>
                                <strong>{{ $rule->label }}</strong>
                                <code>GET {{ $rule->path }}</code>
                                @if($rule->business_context)<small>{{ $rule->business_context }}</small>@endif
                            </div>
                            <form method="POST" action="{{ route('access-rules.destroy', $rule) }}">
                                @csrf
                                @method('DELETE')
                                <button class="btn btn-ghost btn-small" type="submit">Remove</button>
                            </form>
                        </div>
                    @empty
                        <div class="empty">Belum ada boundary rule untuk identity ini.</div>
                    @endforelse
                </div>
            </article>
        @empty
            <div class="empty">Belum ada test identity. Tambahkan akun uji untuk memulai authenticated security validation.</div>
        @endforelse
    </div>
</section>

<script>
document.addEventListener('DOMContentLoaded', () => {
    const select = document.getElementById('auth-type-select');
    const formFields = document.getElementById('form-auth-fields');
    const bearerFields = document.getElementById('bearer-auth-fields');
    const cookieFields = document.getElementById('cookie-auth-fields');
    if (!select || !formFields || !bearerFields || !cookieFields) return;

    const sync = () => {
        const type = select.value;
        formFields.classList.toggle('disabled-box', type !== 'form');
        bearerFields.classList.toggle('disabled-box', type !== 'bearer');
        cookieFields.classList.toggle('disabled-box', type !== 'cookie');
    };

    select.addEventListener('change', sync);
    sync();
});
</script>
