<?php
require __DIR__ . '/../app/bootstrap.php';
$example = file_get_contents(__DIR__ . '/../.env.example');
assert(str_contains($example, 'DB_NAME=sentinelscope'));
assert(str_contains($example, 'ALLOW_PRIVATE_TARGETS=false'));
assert(!str_contains(file_get_contents(__DIR__ . '/../.gitignore'), '/config.php'));
assert(str_contains(file_get_contents(__DIR__ . '/../.gitignore'), '/.env'));
echo "Environment configuration tests passed.\n";

$finding = [
    'severity' => 'high', 'status' => 'high_confidence', 'confidence' => 80, 'manual_review_required' => 0,
    'evidence_summary' => 'CSP is missing.', 'description' => 'No Content-Security-Policy header was returned.',
    'developer_impact' => 'Injected scripts run with fewer restrictions.', 'remediation' => 'Add a strict CSP.',
    'fingerprint' => 'headers.csp_missing', 'category' => 'Security Headers', 'cwe' => 'CWE-693',
    'owasp' => 'A02:2025 Security Misconfiguration', 'wstg' => 'WSTG-CONF-12', 'parameter' => null,
    'parameter_location' => null, 'affected_url' => 'https://example.com/', 'title' => 'Browser has no content execution policy',
    'evidence' => json_encode(['reason' => 'No CSP header.']),
];
$html = renderFinding($finding);
assert(str_contains($html, 'HIGH'));
assert(str_contains($html, 'High Confidence'));
assert(str_contains($html, 'CWE-693'));
assert(!str_contains($html, '<script>'));
echo "Finding rendering tests passed.\n";
