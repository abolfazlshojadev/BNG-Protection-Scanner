<?php
/*
BNG 1.0.1 CryptographySecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Cryptography Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

/*** Begin Cryptography Security Module ***/

final class ProtectionCryptographySecurity implements ProtectionSecurityModule
{
private string $rootPath;
private int $maxFiles;
private int $maxBytes;

public function __construct(
string $rootPath,
int $maxFiles = 3000,
int $maxBytes = 2097152
) {
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot) || !is_readable($realRoot)) {
throw new InvalidArgumentException('Invalid cryptography scan root.');
}

$this->rootPath = rtrim($realRoot, DIRECTORY_SEPARATOR);

if ($this->rootPath === '') {
$this->rootPath = DIRECTORY_SEPARATOR;
}

$this->maxFiles = max(1, min($maxFiles, 20000));
$this->maxBytes = max(1024, min($maxBytes, 10485760));
}

public function id(): string
{
return 'cryptography.security';
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
$maxFiles = min($this->maxFiles, $context->maxFiles());
$maxBytes = min($this->maxBytes, $context->maxBytes());
$maxFindings = $context->maxFindings();
$limitReached = false;
$skippedLarge = 0;
$unreadable = 0;
$patternErrors = 0;

$prefix = $this->rootPath === DIRECTORY_SEPARATOR
? DIRECTORY_SEPARATOR
: $this->rootPath . DIRECTORY_SEPARATOR;

$extensions = ['php', 'phtml', 'inc'];

$patterns = [
'weak_hash_for_security' => '~\b(?:md5|sha1)\s*\([^)]{0,300}\)~i',
'weak_random_generator' => '~\b(?:rand|mt_rand)\s*\(~i',
'legacy_mcrypt_usage' => '~\b(?:mcrypt_encrypt|mcrypt_decrypt|mcrypt_create_iv)\s*\(~i',
'ecb_cipher_mode' => '~\b(?:MCRYPT_MODE_ECB|OPENSSL_RAW_DATA\s*\|\s*OPENSSL_ZERO_PADDING)\b~i',
'insecure_tls_verification_disabled' => '~\b(?:CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST)\s*,\s*(?:false\b|0\b|["\']0["\'])~i',
'weak_password_digest' => '~\b(?:md5|sha1)\s*\(\s*\$(?:password|passwd|secret|token)\b~i',
'weak_random_for_token' => '~\b(?:rand|mt_rand)\s*\([^)]*\).{0,150}\b(?:token|secret|nonce|password|key)\b~is'
];

try {
foreach ($context->files() as $entry) {
if (count($findings) >= $maxFindings) {
$limitReached = true;
break;
}

if ($context->deadlineExceeded()) {
if (count($findings) < $maxFindings) {
$findings[] = [
'type' => 'scan_time_limit',
'severity' => 'warning',
'message' => 'Module scan time limit reached; remaining files were not checked.'
];
}
$limitReached = true;
break;
}

if (!in_array(strtolower((string)($entry['ext'] ?? '')), $extensions, true)) {
continue;
}

if ($filesChecked >= $maxFiles) {
if (count($findings) < $maxFindings) {
$findings[] = [
'type' => 'scan_limit',
'severity' => 'warning',
'message' => 'Cryptography scan file limit reached.'
];
}
$limitReached = true;
break;
}

$path = $entry['path'] ?? null;

if (!is_string($path)) {
continue;
}

$realPath = realpath($path);

if (
$realPath === false ||
!is_file($realPath) ||
!is_readable($realPath) ||
strpos($realPath, $prefix) !== 0
) {
continue;
}

/* Do not report the scanner's own rule definitions as application findings. */
$selfPath = realpath(__FILE__);
if ($selfPath !== false && $realPath === $selfPath) {
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

if ($matches !== [] && count($findings) < $maxFindings) {
$findings[] = [
'type' => 'cryptography_security_review',
'severity' => 'review',
'file' => str_replace(DIRECTORY_SEPARATOR, '/', substr($realPath, strlen($prefix))),
'indicators' => $matches,
'message' => 'Review cryptographic algorithm choices, random number generation, and TLS verification settings.'
];
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Cryptography security scan failed.'
);
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
'max_findings' => $maxFindings,
'scan_limit_reached' => $limitReached,
'files_skipped_too_large' => $skippedLarge,
'files_unreadable' => $unreadable,
'pattern_errors' => $patternErrors
]
);
}
}

/*** End Cryptography Security Module ***/

/*** End Protection Cryptography Security ***/
?>