<?php

namespace App\Services\SecurityAudit;

use Illuminate\Support\Collection;

class ScoreCalculator
{
    public function calculate(Collection $findings): int
    {
        $weights = [
            'critical' => 28,
            'high' => 16,
            'medium' => 7,
            'low' => 2,
            'info' => 0,
        ];

        $deduction = $findings->sum(fn ($finding) => $weights[$finding->severity] ?? 0);

        return max(0, min(100, 100 - $deduction));
    }
}
