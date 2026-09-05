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
        'baseline_session_id',
        'name',
        'target_url',
        'environment',
        'profile',
        'status',
        'progress',
        'current_stage',
        'score',
        'grade',
        'compliance_score',
        'risk_delta',
        'new_findings_count',
        'resolved_findings_count',
        'selected_modules',
        'config',
        'schedule_frequency',
        'next_run_at',
        'last_scheduled_at',
        'verification_token',
        'verified_at',
        'started_at',
        'completed_at',
        'error_message',
        'metadata',
    ];

    protected function casts(): array
    {
        return [
            'selected_modules' => 'array',
            'config' => 'array',
            'metadata' => 'array',
            'verified_at' => 'datetime',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
            'next_run_at' => 'datetime',
            'last_scheduled_at' => 'datetime',
            'score' => 'integer',
            'compliance_score' => 'integer',
            'risk_delta' => 'integer',
            'new_findings_count' => 'integer',
            'resolved_findings_count' => 'integer',
            'progress' => 'integer',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function baseline(): BelongsTo
    {
        return $this->belongsTo(self::class, 'baseline_session_id');
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

    public function isScheduled(): bool
    {
        return filled($this->schedule_frequency) && $this->next_run_at !== null;
    }
}
