<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityFinding extends Model
{
    protected $fillable = [
        'security_session_id',
        'module',
        'severity',
        'title',
        'description',
        'evidence',
        'remediation',
        'status',
    ];

    public function session(): BelongsTo
    {
        return $this->belongsTo(SecuritySession::class, 'security_session_id');
    }
}
