<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityAgentManifest extends Model
{
    protected $fillable = [
        'security_session_id',
        'source_label',
        'framework',
        'framework_version',
        'routes_count',
        'manifest',
        'received_at',
    ];

    protected function casts(): array
    {
        return [
            'manifest' => 'array',
            'routes_count' => 'integer',
            'received_at' => 'datetime',
        ];
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(SecuritySession::class, 'security_session_id');
    }
}
