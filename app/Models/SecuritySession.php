<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class SecuritySession extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'name',
        'target_url',
        'environment',
        'profile',
        'status',
        'progress',
        'current_stage',
        'score',
        'selected_modules',
        'config',
        'verification_token',
        'verified_at',
        'started_at',
        'completed_at',
        'error_message',
    ];

    protected function casts(): array
    {
        return [
            'selected_modules' => 'array',
            'config' => 'array',
            'verified_at' => 'datetime',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
            'score' => 'integer',
            'progress' => 'integer',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function findings(): HasMany
    {
        return $this->hasMany(SecurityFinding::class)->orderByRaw("CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END");
    }

    public function logs(): HasMany
    {
        return $this->hasMany(SecurityLog::class)->latest('id');
    }

    public function isVerified(): bool
    {
        return $this->verified_at !== null;
    }

    public function canRun(): bool
    {
        return $this->isVerified() && ! in_array($this->status, ['queued', 'running'], true);
    }
}
