<?php
/*
BNG Protection 1.0.1
Web Scanner Entry Point
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, private');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

function bng_scan_response(int $status, array $data): never
{
http_response_code($status);
echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
header('Allow: POST');
bng_scan_response(405, [
'ok' => false,
'error' => 'method_not_allowed'
]);
}

$secretFile = dirname(__DIR__) . '/keys/scanner-secret-key.php';

if (!is_file($secretFile) || !is_readable($secretFile)) {
error_log('BNG Protection: Secret configuration is unavailable.');
bng_scan_response(503, [
'ok' => false,
'error' => 'service_unavailable'
]);
}

try {
$secret = require $secretFile;
} catch (Throwable $e) {
error_log('BNG Protection: Secret configuration could not be loaded.');
bng_scan_response(503, [
'ok' => false,
'error' => 'service_unavailable'
]);
}

if (!is_string($secret) || strlen($secret) < 32) {
error_log('BNG Protection: Secret configuration is invalid.');
bng_scan_response(503, [
'ok' => false,
'error' => 'service_unavailable'
]);
}

$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$providedToken = '';

if (preg_match('/^Bearer\s+(\S+)$/i', $authorization, $matches) === 1) {
$providedToken = $matches[1];
}

if ($providedToken === '' || !hash_equals($secret, $providedToken)) {
bng_scan_response(401, [
'ok' => false,
'error' => 'unauthorized'
]);
}

try {
$scannerDir = dirname(__DIR__) . '/scanner';
$bootstrap = $scannerDir . '/bootstrap.php';

if (!is_file($bootstrap) || !is_readable($bootstrap)) {
throw new RuntimeException('Scanner bootstrap is unavailable.');
}

require_once $bootstrap;

$scanRoot = realpath(dirname(__DIR__, 2));

if ($scanRoot === false || !is_dir($scanRoot) || !is_readable($scanRoot)) {
throw new RuntimeException('Scan root is unavailable.');
}

if (!function_exists('protection_create_scanner')) {
throw new RuntimeException('Scanner factory is unavailable.');
}

$scanner = protection_create_scanner($scanRoot);
$result = $scanner->run();

if (!is_array($result) || $result === []) {
bng_scan_response(500, [
'ok' => false,
'error' => 'invalid_scanner_result'
]);
}

bng_scan_response(200, [
'ok' => true,
'scanner' => 'BNG Protection',
'version' => defined('PROTECTION_VERSION') ? PROTECTION_VERSION : 'unknown',
'result' => $result
]);
} catch (Throwable $e) {
error_log('BNG Protection scan failed: ' . $e->getMessage());

bng_scan_response(500, [
'ok' => false,
'error' => 'scan_failed',
'message' => 'Scan failed. Check the server error log.'
]);
}
?>