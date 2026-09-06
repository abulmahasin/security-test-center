<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityAccessRule extends Model
{
    protected $fillable = [
        'security_session_id',
        'security_identity_id',
        'label',
        'kind',
        'path',
        'expectation',
        'business_context',
    ];

    public function session(): BelongsTo
    {
        return $this->belongsTo(SecuritySession::class, 'security_session_id');
    }

    public function identity(): BelongsTo
    {
        return $this->belongsTo(SecurityIdentity::class, 'security_identity_id');
    }
}
