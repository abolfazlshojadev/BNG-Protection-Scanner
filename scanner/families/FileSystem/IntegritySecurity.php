<?php
/*
BNG 1.0.1 IntegritySecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Integrity Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionIntegritySecurity implements ProtectionSecurityModule
{
private array $baseline = [];

public function __construct(array $baseline = [])
{
$normalized = [];

foreach ($baseline as $relativePath => $expectedHash) {
$relativePath = (string) $relativePath;

if (!is_string($expectedHash)) {
throw new InvalidArgumentException('Invalid integrity baseline entry.');
}

if ($relativePath === '' || str_contains($relativePath, "\0")) {
throw new InvalidArgumentException('Invalid baseline path.');
}

if (str_contains($relativePath, '\\') || str_starts_with($relativePath, '/')) {
throw new InvalidArgumentException('Baseline paths must be relative.');
}

foreach (explode('/', $relativePath) as $segment) {
if ($segment === '' || $segment === '.' || $segment === '..') {
throw new InvalidArgumentException('Invalid baseline path segment.');
}
}

if (preg_match('/^[a-f0-9]{64}$/iD', $expectedHash) !== 1) {
throw new InvalidArgumentException('Baseline entries must contain SHA-256 hashes.');
}

$normalized[$relativePath] = strtolower($expectedHash);
}

$this->baseline = $normalized;
}

public function id(): string
{
return 'integrity.security';
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
$checked = 0;
$maxFindings = $context->maxFindings();
$root = $context->scanRoot();
$prefix = $root === DIRECTORY_SEPARATOR ? DIRECTORY_SEPARATOR : $root . DIRECTORY_SEPARATOR;

try {
if ($this->baseline === []) {
$findings[] = [
'type' => 'integrity_baseline_missing',
'severity' => 'warning',
'message' => 'No integrity baseline is configured; file changes cannot be detected.'
];
}

foreach ($this->baseline as $relativePath => $expectedHash) {
$relativePath = (string) $relativePath;

if (count($findings) >= $maxFindings || $context->deadlineExceeded()) {
break;
}

$fullPath = $root . DIRECTORY_SEPARATOR
. str_replace('/', DIRECTORY_SEPARATOR, $relativePath);

if (is_link($fullPath)) {
$findings[] = [
'type' => 'integrity_symlink',
'severity' => 'high',
'file' => $relativePath,
'message' => 'A baseline file path is now a symbolic link.'
];
continue;
}

if (!file_exists($fullPath)) {
$findings[] = [
'type' => 'integrity_missing',
'severity' => 'high',
'file' => $relativePath,
'message' => 'A file in the trusted baseline is missing.'
];
continue;
}

$realFile = realpath($fullPath);

if ($realFile === false || strpos($realFile, $prefix) !== 0 || !is_file($realFile)) {
$findings[] = [
'type' => 'integrity_path_invalid',
'severity' => 'high',
'file' => $relativePath,
'message' => 'The baseline path is not a regular file inside the scan root.'
];
continue;
}

if (!is_readable($realFile)) {
$findings[] = [
'type' => 'integrity_unreadable',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'The baseline file cannot be read.'
];
continue;
}

$actualHash = hash_file('sha256', $realFile);

if (!is_string($actualHash)) {
$findings[] = [
'type' => 'integrity_hash_error',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'Unable to calculate the file hash.'
];
continue;
}

$checked++;

if (!hash_equals($expectedHash, $actualHash)) {
$findings[] = [
'type' => 'integrity_changed',
'severity' => 'high',
'file' => $relativePath,
'expected_sha256' => $expectedHash,
'actual_sha256' => $actualHash,
'message' => 'The file hash differs from the trusted baseline.'
];
}
}

if ($this->baseline !== []) {
$watched = ['php', 'phtml', 'phar', 'php5', 'php7', 'inc', 'htaccess'];

foreach ($context->files() as $entry) {
if (count($findings) >= $maxFindings || $context->deadlineExceeded()) {
break;
}

if (!in_array($entry['ext'], $watched, true)) {
continue;
}

if (!isset($this->baseline[$entry['relative']])) {
$findings[] = [
'type' => 'integrity_unknown_file',
'severity' => 'review',
'file' => $entry['relative'],
'message' => 'This file is not part of the trusted baseline.'
];
}
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Integrity scan failed.'
);
}

$findings = array_slice($findings, 0, $maxFindings);

return ProtectionModuleResult::fromFindings(
$this->id(),
$findings,
[
'files_checked' => $checked,
'baseline_entries' => count($this->baseline)
]
);
}
}

/*** End Protection Integrity Security ***/

?>