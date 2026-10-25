<?php
/*
BNG 1.0.1 PatternSecurityModule
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Pattern Security Module ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

abstract class ProtectionPatternSecurityModule implements ProtectionSecurityModule
{
protected int $maxFiles;
protected int $maxBytes;
protected array $extensions = ['php', 'phtml', 'inc'];
protected array $patterns = [];
protected array $suspiciousNames = [];
protected array $highIndicators = [];
protected bool $readsContent = true;
protected string $reviewMessage = 'Potential security indicators were found. Manual verification is required.';
protected int $patternErrors = 0;
protected string $lastPatternError = '';

public function __construct(int $maxFiles = 3000, int $maxBytes = 2097152)
{
$this->maxFiles = max(1, min($maxFiles, 20000));
$this->maxBytes = max(1024, min($maxBytes, 10485760));
}

abstract public function id(): string;

public function isEnabled(): bool
{
return true;
}

public function reset(): void
{
$this->patternErrors = 0;
$this->lastPatternError = '';
}

protected function contextFindings(ProtectionScanContext $context): array
{
return [];
}

protected function extraMetadata(): array
{
return [];
}

protected function extraFindings(string $content, array $entry): array
{
return [];
}

protected function matches(string $name, string $pattern, string $content): bool
{
$result = preg_match($pattern, $content);

if ($result === false) {
$this->patternErrors++;

if ($this->lastPatternError === '') {
$this->lastPatternError = $name . ': ' . preg_last_error_msg();
}

return false;
}

return $result === 1;
}

protected function analyze(string $content, array $entry): array
{
$matched = [];

foreach ($this->patterns as $name => $pattern) {
if ($this->matches((string) $name, $pattern, $content)) {
$matched[] = (string) $name;
}
}

return $matched;
}

protected function matchNames(array $entry): array
{
$matched = [];

foreach ($this->suspiciousNames as $pattern => $description) {
if (
$this->matches((string) $description, (string) $pattern, $entry['name']) ||
$this->matches((string) $description, (string) $pattern, $entry['relative'])
) {
$matched[] = $description;
}
}

return array_values(array_unique($matched));
}

public function execute(ProtectionScanContext $context): ProtectionModuleResult
{
$this->reset();

$findings = [];
$checked = 0;
$skippedLarge = 0;
$unreadable = 0;
$limitReached = false;
$findingLimitReached = false;
$maxFiles = min($this->maxFiles, $context->maxFiles());
$maxBytes = min($this->maxBytes, $context->maxBytes());
$maxFindings = $context->maxFindings();

try {
foreach ($this->contextFindings($context) as $contextFinding) {
if (count($findings) >= $maxFindings) {
$findingLimitReached = true;
break;
}

$findings[] = $contextFinding;
}

if (!$findingLimitReached) {
foreach ($context->files() as $entry) {
if (count($findings) >= $maxFindings) {
$findingLimitReached = true;
break;
}

if ($context->deadlineExceeded()) {
$findings[] = [
'type' => 'scan_time_limit',
'severity' => 'warning',
'message' => 'Scan time limit reached; remaining files were not checked.'
];
$limitReached = true;
break;
}

$nameMatches = $this->matchNames($entry);

if ($nameMatches !== []) {
$findings[] = [
'type' => 'suspicious_file_name',
'severity' => 'review',
'file' => $entry['relative'],
'indicators' => $nameMatches,
'message' => 'Review this file and verify whether it should be present or publicly accessible.'
];

if (count($findings) >= $maxFindings) {
$findingLimitReached = true;
break;
}
}

if (!$this->readsContent) {
continue;
}

if (!in_array($entry['ext'], $this->extensions, true)) {
continue;
}

if ($checked >= $maxFiles) {
$findings[] = [
'type' => 'scan_limit',
'severity' => 'warning',
'message' => 'Module scan file limit reached.'
];
$limitReached = true;
break;
}

if ($entry['size'] > $maxBytes) {
$skippedLarge++;
continue;
}

$content = @file_get_contents($entry['path']);

if (!is_string($content)) {
$unreadable++;
continue;
}

$checked++;

$indicators = array_values(array_unique($this->analyze($content, $entry)));

if ($indicators !== []) {
$severity = array_intersect($indicators, $this->highIndicators) !== []
? 'high'
: 'review';

$findings[] = [
'type' => $this->id() . '_review',
'severity' => $severity,
'file' => $entry['relative'],
'indicators' => $indicators,
'message' => $this->reviewMessage
];
}

if (count($findings) < $maxFindings) {
foreach ($this->extraFindings($content, $entry) as $extraFinding) {
$findings[] = $extraFinding;

if (count($findings) >= $maxFindings) {
$findingLimitReached = true;
break;
}
}
}

if (count($findings) >= $maxFindings) {
$findingLimitReached = true;
break;
}
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Security module scan failed.'
);
}

if (count($findings) > $maxFindings) {
$findingLimitReached = true;
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

if ($this->patternErrors > 0) {
$findings[] = [
'type' => 'pattern_engine_error',
'severity' => 'warning',
'count' => $this->patternErrors,
'detail' => $this->lastPatternError,
'message' => 'One or more patterns failed to execute; results may be incomplete.'
];
}

return ProtectionModuleResult::fromFindings(
$this->id(),
$findings,
array_merge(
[
'files_checked' => $checked,
'files_skipped_too_large' => $skippedLarge,
'files_unreadable' => $unreadable,
'max_files' => $maxFiles,
'max_bytes_per_file' => $maxBytes,
'max_findings' => $maxFindings,
'finding_limit_reached' => $findingLimitReached,
'scan_limit_reached' => $limitReached
],
$this->extraMetadata()
)
);
}
}

/*** End Protection Pattern Security Module ***/

?>