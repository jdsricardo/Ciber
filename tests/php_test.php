<?php
$example = file_get_contents(__DIR__ . '/../.env.example');
assert(str_contains($example, 'DB_NAME=sentinelscope'));
assert(str_contains($example, 'ALLOW_PRIVATE_TARGETS=false'));
assert(!str_contains(file_get_contents(__DIR__ . '/../.gitignore'), '/config.php'));
assert(str_contains(file_get_contents(__DIR__ . '/../.gitignore'), '/.env'));
echo "Environment configuration tests passed.\n";
