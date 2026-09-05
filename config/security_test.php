<?php

return [
    'allow_private_targets' => filter_var(env('SECURITY_TEST_ALLOW_PRIVATE_TARGETS', false), FILTER_VALIDATE_BOOL),
    'allowed_ports' => array_values(array_filter(array_map('intval', explode(',', env('SECURITY_TEST_ALLOWED_PORTS', '80,443,8080,8443'))))),
    'http_timeout' => (int) env('SECURITY_TEST_HTTP_TIMEOUT', 8),
    'max_redirects' => (int) env('SECURITY_TEST_MAX_REDIRECTS', 4),
    'verification_path' => '/.well-known/security-test-center.txt',
    'load' => [
        'max_vus' => (int) env('SECURITY_TEST_LOAD_MAX_VUS', 20),
        'max_rps' => (int) env('SECURITY_TEST_LOAD_MAX_RPS', 20),
        'max_duration' => (int) env('SECURITY_TEST_LOAD_MAX_DURATION', 30),
        'max_requests' => (int) env('SECURITY_TEST_LOAD_MAX_REQUESTS', 600),
    ],
];
