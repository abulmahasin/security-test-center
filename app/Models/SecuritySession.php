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
        'monitoring_enabled',
        'schedule_interval_minutes',
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
            'monitoring_enabled' => 'boolean',
            'schedule_interval_minutes' => 'integer',
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

    public function identities(): HasMany
    {
        return $this->hasMany(SecurityIdentity::class);
    }

    public function accessRules(): HasMany
    {
        return $this->hasMany(SecurityAccessRule::class);
    }

    public function guestBoundaries(): HasMany
    {
        return $this->hasMany(SecurityGuestBoundary::class);
    }

    public function accountTests(): HasMany
    {
        return $this->hasMany(SecurityAccountTest::class);
    }

    public function agentManifests(): HasMany
    {
        return $this->hasMany(SecurityAgentManifest::class);
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
        return $this->monitoring_enabled
            && $this->schedule_interval_minutes !== null
            && $this->next_run_at !== null;
    }

    public function monitoringLabel(): string
    {
        if (! $this->monitoring_enabled || ! $this->schedule_interval_minutes) {
            return 'Manual only';
        }

        $minutes = $this->schedule_interval_minutes;

        if ($minutes % 10080 === 0) {
            return 'Every '.($minutes / 10080).' week(s)';
        }

        if ($minutes % 1440 === 0) {
            return 'Every '.($minutes / 1440).' day(s)';
        }

        return 'Every '.($minutes / 60).' hour(s)';
    }
}
