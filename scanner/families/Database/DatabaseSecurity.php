<?php
/*
BNG 1.0.1 DatabaseSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Database Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

/*** Begin Database Security Module ***/

final class ProtectionDatabaseSecurity implements ProtectionSecurityModule
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
throw new InvalidArgumentException('Invalid database scan root.');
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
return 'database.security';
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
'embedded_database_credentials' => '~(?:["\'](?:DB_PASSWORD|DB_PASS|database_password|db_password)["\']\s*=>\s*["\'][^"\']+["\']|\$(?:db_password|database_password)\s*=\s*["\'][^"\']+["\'])~i',
'weak_database_connection_options' => '~\b(?:PDO::ATTR_EMULATE_PREPARES)\s*=>\s*true\b~i',
'disabled_database_error_handling' => '~\b(?:mysqli_report\s*\(\s*MYSQLI_REPORT_OFF\s*\)|PDO::ATTR_ERRMODE\s*=>\s*PDO::ERRMODE_SILENT)\b~i',
'raw_query_concatenation' => '~\b(?:mysqli_query|pg_query|sqlite_query)\s*\([^;]{0,400}\.\s*\$[a-z_][a-z0-9_]*~i',
'request_input_in_query' => '~\b(?:mysqli_query|pg_query|sqlite_query)\s*\([^;]{0,500}\$_(?:GET|POST|REQUEST|COOKIE)\s*\[~i',
'unsafe_dynamic_table_name' => '~\b(?:FROM|JOIN|UPDATE|INTO|DELETE\s+FROM)\s*[\'"]?\s*\.\s*\$[a-z_][a-z0-9_]*~i'
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
'message' => 'Database scan file limit reached.'
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
'type' => 'database_security_review',
'severity' => 'review',
'file' => str_replace(DIRECTORY_SEPARATOR, '/', substr($realPath, strlen($prefix))),
'indicators' => $matches,
'message' => 'Review database credentials, query construction, prepared statements, and database error handling.'
];
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Database security scan failed.'
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

/*** End Database Security Module ***/

/*** End Protection Database Security ***/
?>