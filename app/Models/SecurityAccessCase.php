<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class SecurityAccessCase extends Model
{
    protected $fillable = [
        'security_session_id',
        'security_test_identity_id',
        'name',
        'kind',
        'method',
        'path',
        'expected_policy',
        'business_context',
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

    public function identity(): BelongsTo
    {
        return $this->belongsTo(SecurityTestIdentity::class, 'security_test_identity_id');
    }

    public function results(): HasMany
    {
        return $this->hasMany(SecurityAccessResult::class)->latest('executed_at');
    }
}
