<?php
/*
BNG 1.0.1 DependencySecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Dependency Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

/*** Begin Dependency Security Module ***/

final class ProtectionDependencySecurity implements ProtectionSecurityModule
{
private int $maxFiles;
private int $maxBytes;

public function __construct(
string $rootPath,
int $maxFiles = 3000,
int $maxBytes = 2097152
) {
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot)) {
throw new InvalidArgumentException('Invalid dependency scan root.');
}

$this->maxFiles = max(1, min($maxFiles, 20000));
$this->maxBytes = max(1024, min($maxBytes, 10485760));
}

public function id(): string
{
return 'dependency.security';
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
$maxFindings = $context->maxFindings();
$maxFiles = min($this->maxFiles, $context->maxFiles());
$maxBytes = min($this->maxBytes, $context->maxBytes());
$manifestNames = [
'composer.json',
'composer.lock',
'package.json',
'package-lock.json',
'npm-shrinkwrap.json',
'yarn.lock',
'pnpm-lock.yaml'
];
$knownFiles = [];
$root = $context->scanRoot();
$prefix = $root === DIRECTORY_SEPARATOR
? DIRECTORY_SEPARATOR
: rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

try {
foreach ($context->files() as $entry) {
if ($context->deadlineExceeded()) {
$findings[] = [
'type' => 'scan_time_limit',
'severity' => 'warning',
'message' => 'Dependency scan time limit reached; remaining files were not checked.'
];
break;
}

if ($filesChecked >= $maxFiles) {
$findings[] = [
'type' => 'scan_limit',
'severity' => 'warning',
'message' => 'Dependency scan file limit reached.'
];
break;
}

$path = $entry['path'] ?? null;
$name = $entry['name'] ?? null;

if (!is_string($path) || !is_string($name)) {
continue;
}

if (!in_array($name, $manifestNames, true)) {
continue;
}

if (is_link($path)) {
continue;
}

$realPath = realpath($path);

if (
$realPath === false ||
!is_file($realPath) ||
!is_readable($realPath) ||
($root !== DIRECTORY_SEPARATOR && strpos($realPath, $prefix) !== 0)
) {
continue;
}

$size = @filesize($realPath);

if ($size === false) {
continue;
}

$filesChecked++;

$relativePath = $entry['relative'] ?? basename($realPath);

if (!is_string($relativePath)) {
$relativePath = basename($realPath);
}

$relativePath = str_replace('\\', '/', $relativePath);

if ($size > $maxBytes) {
$findings[] = [
'type' => 'manifest_not_scanned',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'Dependency manifest exceeds the configured size limit.'
];

if (count($findings) >= $maxFindings) {
break;
}

continue;
}

$content = @file_get_contents($realPath);

if (!is_string($content)) {
$findings[] = [
'type' => 'manifest_read_failed',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'Dependency manifest could not be read.'
];

if (count($findings) >= $maxFindings) {
break;
}

continue;
}

$knownFiles[] = $relativePath;
$baseName = basename($realPath);

if ($baseName === 'composer.json' || $baseName === 'package.json') {
$decoded = json_decode($content, true);

if (!is_array($decoded)) {
$findings[] = [
'type' => 'invalid_dependency_manifest',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'Dependency manifest is not valid JSON.'
];
} else {
if (
$baseName === 'composer.json' &&
isset($decoded['minimum-stability']) &&
is_string($decoded['minimum-stability']) &&
strtolower($decoded['minimum-stability']) === 'dev'
) {
$findings[] = [
'type' => 'development_dependencies_allowed',
'severity' => 'review',
'file' => $relativePath,
'message' => 'Review whether development-only dependency versions are appropriate for production.'
];
}

if (
$baseName === 'composer.json' &&
isset($decoded['config']['allow-plugins']) &&
is_array($decoded['config']['allow-plugins'])
) {
foreach ($decoded['config']['allow-plugins'] as $plugin => $allowed) {
if ($allowed === true) {
$findings[] = [
'type' => 'composer_plugin_allowed',
'severity' => 'review',
'file' => $relativePath,
'plugin' => is_string($plugin) ? substr($plugin, 0, 200) : 'unknown',
'message' => 'Review whether this Composer plugin is trusted and necessary.'
];

if (count($findings) >= $maxFindings) {
break;
}
}
}
}
}
}

if ($baseName === 'composer.lock' || $baseName === 'package-lock.json' || $baseName === 'npm-shrinkwrap.json') {
$decoded = json_decode($content, true);

if (!is_array($decoded)) {
$findings[] = [
'type' => 'invalid_lockfile',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'Dependency lockfile is not valid JSON.'
];
}
}

if (
($baseName === 'yarn.lock' || $baseName === 'pnpm-lock.yaml') &&
trim($content) === ''
) {
$findings[] = [
'type' => 'empty_lockfile',
'severity' => 'warning',
'file' => $relativePath,
'message' => 'Dependency lockfile is empty.'
];
}

if (count($findings) >= $maxFindings) {
break;
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Dependency security scan failed.'
);
}

$findings = array_slice($findings, 0, $maxFindings);

return ProtectionModuleResult::fromFindings(
$this->id(),
$findings,
[
'files_checked' => $filesChecked,
'manifests_found' => count($knownFiles),
'max_files' => $maxFiles,
'max_bytes_per_file' => $maxBytes
]
);
}
}

/*** End Dependency Security Module ***/

/*** End Protection Dependency Security ***/
?>