<?php

return [
    'driver' => env('HASH_DRIVER', 'bcrypt'),
    'bcrypt' => [
        'rounds' => env('BCRYPT_ROUNDS', 12),
        'verify' => env('HASH_VERIFY', true),
        'limit' => env('HASH_LIMIT', null),
    ],
    'argon' => [
        'memory' => 65536,
        'threads' => 1,
        'time' => 4,
        'verify' => env('HASH_VERIFY', true),
        'limit' => env('HASH_LIMIT', null),
    ],
    'rehash_on_login' => true,
];
