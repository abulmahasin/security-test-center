<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Crypt;

class SecurityIdentity extends Model
{
    protected $fillable = [
        'security_session_id',
        'label',
        'expected_role',
        'auth_type',
        'login_path',
        'username_field',
        'password_field',
        'username',
        'password_encrypted',
        'bearer_token_encrypted',
        'session_cookie_encrypted',
        'success_path',
        'enabled',
    ];

    protected function casts(): array
    {
        return ['enabled' => 'boolean'];
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(SecuritySession::class, 'security_session_id');
    }

    public function accessRules(): HasMany
    {
        return $this->hasMany(SecurityAccessRule::class);
    }

    public function setPassword(?string $password): void
    {
        $this->password_encrypted = filled($password) ? Crypt::encryptString($password) : null;
    }

    public function password(): ?string
    {
        return $this->password_encrypted ? Crypt::decryptString($this->password_encrypted) : null;
    }

    public function setBearerToken(?string $token): void
    {
        $this->bearer_token_encrypted = filled($token) ? Crypt::encryptString($token) : null;
    }

    public function bearerToken(): ?string
    {
        return $this->bearer_token_encrypted ? Crypt::decryptString($this->bearer_token_encrypted) : null;
    }

    public function setSessionCookie(?string $cookie): void
    {
        $this->session_cookie_encrypted = filled($cookie) ? Crypt::encryptString($cookie) : null;
    }

    public function sessionCookie(): ?string
    {
        return $this->session_cookie_encrypted ? Crypt::decryptString($this->session_cookie_encrypted) : null;
    }
}
