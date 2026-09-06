<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class SecurityTestIdentity extends Model
{
    protected $fillable = [
        'security_session_id',
        'name',
        'role_label',
        'auth_type',
        'credentials',
        'enabled',
        'last_verified_at',
        'last_auth_status',
    ];

    protected function casts(): array
    {
        return [
            'credentials' => 'encrypted:array',
            'enabled' => 'boolean',
            'last_verified_at' => 'datetime',
        ];
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(SecuritySession::class, 'security_session_id');
    }

    public function cases(): HasMany
    {
        return $this->hasMany(SecurityAccessCase::class, 'security_test_identity_id');
    }

    public function results(): HasMany
    {
        return $this->hasMany(SecurityAccessResult::class, 'security_test_identity_id');
    }
}
