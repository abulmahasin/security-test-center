<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Crypt;

class SecurityAccountTest extends Model
{
    protected $fillable = [
        'security_session_id',
        'security_identity_id',
        'label',
        'kind',
        'path',
        'config_encrypted',
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
        return $this->belongsTo(SecurityIdentity::class, 'security_identity_id');
    }

    public function setConfig(array $config): void
    {
        $this->config_encrypted = Crypt::encryptString(json_encode($config, JSON_THROW_ON_ERROR));
    }

    public function config(): array
    {
        if (! $this->config_encrypted) {
            return [];
        }

        $decoded = json_decode(Crypt::decryptString($this->config_encrypted), true);

        return is_array($decoded) ? $decoded : [];
    }
}
