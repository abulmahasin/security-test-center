<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityAccessResult extends Model
{
    protected $fillable = [
        'security_access_case_id',
        'security_session_id',
        'security_test_identity_id',
        'outcome',
        'status_code',
        'severity',
        'summary',
        'evidence',
        'remediation',
        'response_bytes',
        'duration_ms',
        'executed_at',
    ];

    protected function casts(): array
    {
        return [
            'status_code' => 'integer',
            'response_bytes' => 'integer',
            'duration_ms' => 'integer',
            'executed_at' => 'datetime',
        ];
    }

    public function securityCase(): BelongsTo
    {
        return $this->belongsTo(SecurityAccessCase::class, 'security_access_case_id');
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(SecuritySession::class, 'security_session_id');
    }

    public function identity(): BelongsTo
    {
        return $this->belongsTo(SecurityTestIdentity::class, 'security_test_identity_id');
    }
}
