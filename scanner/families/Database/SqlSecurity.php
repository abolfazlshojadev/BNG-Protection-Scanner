<?php
/*
BNG 1.0.1 SqlSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection SQL Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

/*** Begin SQL Security Module ***/

final class ProtectionSqlSecurity implements ProtectionSecurityModule
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
throw new InvalidArgumentException('Invalid SQL scan root.');
}

$this->rootPath = rtrim($realRoot, DIRECTORY_SEPARATOR);

if ($this->rootPath === '') {
$this->rootPath = DIRECTORY_SEPARATOR;
}

$this->maxFiles = max(1, min($maxFiles, 10000));
$this->maxBytes = max(1024, min($maxBytes, 10485760));
}

public function id(): string
{
return 'sql.security';
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
'legacy_mysql_api' => '~\bmysql_query\s*\(~i',
'raw_sql_with_request_input' => '~\b(?:mysqli_query|pg_query|sqlite_query)\s*\([^;]{0,500}\$_(?:GET|POST|REQUEST|COOKIE)\s*\[~i',
'string_concatenation_near_query' => '~\b(?:mysqli_query|pg_query)\s*\([^;]{0,300}\.\s*\$[a-z_][a-z0-9_]*~i',
'unsafe_dynamic_sql' => '~\b(?:SELECT|UPDATE|DELETE|INSERT)\b.{0,200}\.\s*\$_(?:GET|POST|REQUEST)\s*\[~is',
'framework_raw_query_with_variable' => '~\b(?:DB::(?:raw|select|statement|unprepared|insert|update|delete)|whereRaw|orderByRaw|havingRaw|selectRaw|groupByRaw|createCommand|createQuery|executeQuery|executeStatement|executeUpdate|setQuery|db_query)\s*\((?:[^;]{0,300}(?:\.\s*\$|\{\$)|\s*\x22[^\x22;]*\$[a-z_])~i'
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
'message' => 'SQL scan file limit reached.'
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
'type' => 'sql_security_review',
'severity' => 'review',
'file' => str_replace(DIRECTORY_SEPARATOR, '/', substr($realPath, strlen($prefix))),
'indicators' => $matches,
'message' => 'Review SQL construction and use parameterized queries for untrusted values.'
];
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'SQL security scan failed.'
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

/*** End SQL Security Module ***/

/*** End Protection SQL Security ***/
?>