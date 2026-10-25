<?php
/*
BNG 1.0.1 HttpSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection HTTP Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionHttpSecurity implements ProtectionSecurityModule
{
private string $rootPath;
private int $maxFiles;
private int $maxBytes;

public function __construct(string $rootPath, int $maxFiles = 3000, int $maxBytes = 2097152)
{
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot)) {
throw new InvalidArgumentException('Invalid HTTP security scan root.');
}

if ($maxFiles < 1 || $maxBytes < 1) {
throw new InvalidArgumentException('Invalid HTTP security scan limits.');
}

$this->rootPath = rtrim($realRoot, DIRECTORY_SEPARATOR);

if ($this->rootPath === '') {
$this->rootPath = DIRECTORY_SEPARATOR;
}

$this->maxFiles = min($maxFiles, 20000);
$this->maxBytes = min($maxBytes, 10485760);
}

public function id(): string
{
return 'http.security';
}

public function isEnabled(): bool
{
return true;
}

public function reset(): void
{
}

public function execute(ProtectionScanContext $context): ProtectionModuleResult
{
$findings = [];
$filesChecked = 0;
$skippedLarge = 0;
$unreadable = 0;
$patternErrors = 0;
$limitReached = false;
$maxFiles = min($this->maxFiles, $context->maxFiles());
$maxBytes = min($this->maxBytes, $context->maxBytes());
$maxFindings = $context->maxFindings();

$prefix = $this->rootPath === DIRECTORY_SEPARATOR
? DIRECTORY_SEPARATOR
: $this->rootPath . DIRECTORY_SEPARATOR;

$extensions = ['php', 'phtml', 'inc', 'conf', 'ini'];
$configNames = ['.htaccess', 'httpd.conf', 'nginx.conf', 'php.ini', '.user.ini'];

$patterns = [
'http_url_in_security_sensitive_code' => '~\b(?:curl_init|file_get_contents|fopen)\s*\(\s*["\']http://~i',
'tls_peer_verification_disabled' => '~\bCURLOPT_SSL_VERIFYPEER\s*,\s*(?:false\b|0\b|["\']0["\'])~i',
'tls_host_verification_disabled' => '~\bCURLOPT_SSL_VERIFYHOST\s*,\s*(?:false\b|0\b|["\']0["\'])~i',
'weak_cookie_flags' => '~\bsetcookie\s*\([^;]{0,500}[\s,\[(]["\']?(?:secure|httponly)["\']?\s*(?:=>|:)\s*false\b~i',
'header_injection_indicator' => '~\bheader\s*\(\s*["\'](?:Location|Set-Cookie)\s*:\s*["\']\s*\.\s*\$~i',
'debug_error_display' => '~\bini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?(?:1|on|true)\b~i',
'insecure_http_redirect' => '~\bheader\s*\(\s*["\']Location:\s*http://~i'
];

try {
foreach ($context->files() as $entry) {
if (count($findings) >= $maxFindings) {
$limitReached = true;
break;
}

if ($context->deadlineExceeded()) {
$findings[] = [
'type' => 'scan_time_limit',
'severity' => 'warning',
'message' => 'HTTP security scan time limit reached; remaining files were not checked.'
];
$limitReached = true;
break;
}

$filename = (string) ($entry['name'] ?? '');
$extension = (string) ($entry['ext'] ?? '');

if (!in_array($extension, $extensions, true) && !in_array($filename, $configNames, true)) {
continue;
}

if ($filesChecked >= $maxFiles) {
$findings[] = [
'type' => 'scan_limit',
'severity' => 'warning',
'message' => 'HTTP security scan file limit reached.'
];
$limitReached = true;
break;
}

$path = $entry['path'] ?? null;

if (!is_string($path)) {
continue;
}

$realPath = realpath($path);

if (
$realPath === false
|| !is_file($realPath)
|| !is_readable($realPath)
|| strpos($realPath, $prefix) !== 0
) {
continue;
}

$size = @filesize($realPath);

if ($size === false || $size > $maxBytes) {
$skippedLarge++;
continue;
}

$content = @file_get_contents($realPath);

if (!is_string($content)) {
$unreadable++;
continue;
}

$filesChecked++;
$matches = [];

foreach ($patterns as $name => $pattern) {
$result = preg_match($pattern, $content);

if ($result === false) {
$patternErrors++;
continue;
}

if ($result === 1) {
$matches[] = $name;
}
}

$relativePath = (string) ($entry['relative'] ?? basename($realPath));

if ($matches !== []) {
$findings[] = [
'type' => 'http_security_review',
'severity' => 'review',
'file' => $relativePath,
'indicators' => $matches,
'message' => 'Review HTTPS usage, TLS verification, cookie flags, redirects, and HTTP response handling.'
];
}

if (
$filename === '.htaccess'
&& $relativePath === '.htaccess'
&& preg_match('~^\s*Options\s+[^#\r\n]*-Indexes\b~im', $content) !== 1
) {
$findings[] = [
'type' => 'directory_listing_setting_review',
'severity' => 'review',
'file' => $relativePath,
'message' => 'Review whether directory listing is disabled by the active web server configuration.'
];
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'HTTP security scan failed.'
);
}

if (count($findings) > $maxFindings) {
$findings = array_slice($findings, 0, $maxFindings);
}

if ($skippedLarge > 0) {
$findings[] = [
'type' => 'files_skipped_too_large',
'severity' => 'warning',
'count' => $skippedLarge,
'message' => 'Files above the size limit were not scanned; results may be incomplete.'
];
}

if ($unreadable > 0) {
$findings[] = [
'type' => 'files_unreadable',
'severity' => 'warning',
'count' => $unreadable,
'message' => 'Some files could not be read and were not scanned; results may be incomplete.'
];
}

if ($patternErrors > 0) {
$findings[] = [
'type' => 'pattern_engine_error',
'severity' => 'warning',
'count' => $patternErrors,
'message' => 'One or more patterns failed to execute; results may be incomplete.'
];
}

return new ProtectionModuleResult(
$this->id(),
$findings === []
? ProtectionModuleResult::STATUS_OK
: ProtectionModuleResult::STATUS_WARNING,
$findings,
[
'files_checked' => $filesChecked,
'max_files' => $maxFiles,
'max_bytes_per_file' => $maxBytes,
'scan_limit_reached' => $limitReached,
'files_skipped_too_large' => $skippedLarge,
'files_unreadable' => $unreadable,
'pattern_errors' => $patternErrors,
'limitations' => 'This is a static source scan; it does not inspect live HTTP responses or prove the active server configuration.'
]
);
}
}

/*** End Protection HTTP Security ***/

?>
