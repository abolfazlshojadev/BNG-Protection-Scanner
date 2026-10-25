<?php
/*
BNG 1.0.1 ScanContext
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Scan Context ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionScanContext
{
private array $options = [];
private string $scanRoot;
private int $maxFiles;
private int $maxBytes;
private int $maxFindings;
private int $maxIndexEntries;
private int $maxSeconds;
private float $startedAt;
private array $excludeDirs = [];
private array $excludePaths = [];
private ?array $files = null;
private array $links = [];
private array $skippedDirectories = [];
private bool $indexTruncated = false;

public function __construct(array $options = [])
{
$root = $options['scan_root'] ?? dirname(__DIR__);

if (!is_string($root) || trim($root) === '') {
throw new InvalidArgumentException('Invalid scan root.');
}

$realRoot = realpath($root);

if ($realRoot === false || !is_dir($realRoot) || !is_readable($realRoot)) {
throw new InvalidArgumentException('Scan root must be a readable directory.');
}

$this->scanRoot = rtrim($realRoot, DIRECTORY_SEPARATOR);

if ($this->scanRoot === '') {
$this->scanRoot = DIRECTORY_SEPARATOR;
}

$this->maxFiles = $this->boundedInt($options['max_files'] ?? 5000, 1, 20000);
$this->maxBytes = $this->boundedInt($options['max_bytes'] ?? 2097152, 1024, 10485760);
$this->maxFindings = $this->boundedInt($options['max_findings'] ?? 500, 1, 5000);
$this->maxIndexEntries = $this->boundedInt($options['max_index_entries'] ?? 50000, 1000, 200000);
$this->maxSeconds = $this->boundedInt($options['max_seconds'] ?? 25, 1, 3600);

$exclude = $options['exclude_dirs'] ?? ['.git', '.svn', 'node_modules'];

if (!is_array($exclude)) {
$exclude = [];
}

foreach ($exclude as $name) {
if (is_string($name) && $name !== '') {
$this->excludeDirs[] = strtolower($name);
}
}

$excludePaths = $options['exclude_paths'] ?? [];

if (!is_array($excludePaths)) {
$excludePaths = [];
}

foreach ($excludePaths as $excludePath) {
if (!is_string($excludePath)) {
continue;
}

$excludePath = trim(str_replace('\\', '/', $excludePath), '/');

if ($excludePath !== '') {
$this->excludePaths[] = strtolower($excludePath);
}
}

$this->startedAt = microtime(true);

$this->options = $options;
$this->options['scan_root'] = $this->scanRoot;
$this->options['max_files'] = $this->maxFiles;
$this->options['max_bytes'] = $this->maxBytes;
$this->options['max_findings'] = $this->maxFindings;
$this->options['max_index_entries'] = $this->maxIndexEntries;
$this->options['max_seconds'] = $this->maxSeconds;
$this->options['exclude_dirs'] = $this->excludeDirs;
$this->options['exclude_paths'] = $this->excludePaths;
}

private function boundedInt(mixed $value, int $min, int $max): int
{
if (!is_numeric($value)) {
return $min;
}

return max($min, min($max, (int) $value));
}

public function get(string $key, mixed $default = null): mixed
{
return $this->options[$key] ?? $default;
}

public function all(): array
{
return $this->options;
}

public function scanRoot(): string
{
return $this->scanRoot;
}

public function maxFiles(): int
{
return $this->maxFiles;
}

public function maxBytes(): int
{
return $this->maxBytes;
}

public function maxFindings(): int
{
return $this->maxFindings;
}

public function maxSeconds(): int
{
return $this->maxSeconds;
}

public function elapsedSeconds(): float
{
return microtime(true) - $this->startedAt;
}

public function deadlineExceeded(): bool
{
return $this->elapsedSeconds() > $this->maxSeconds;
}

public function files(): array
{
if ($this->files !== null) {
return $this->files;
}

$this->files = [];

$prefix = $this->scanRoot === DIRECTORY_SEPARATOR
? DIRECTORY_SEPARATOR
: $this->scanRoot . DIRECTORY_SEPARATOR;
$prefixLength = strlen($prefix);
$excluded = $this->excludeDirs;

$filter = function ($current, $key, $iterator) use ($excluded): bool {
if (!$current instanceof SplFileInfo) {
return false;
}

if ($current->isLink()) {
$this->links[$current->getPathname()] = true;

return false;
}

if ($current->isDir() && in_array(strtolower($current->getFilename()), $excluded, true)) {
$this->skippedDirectories[$current->getPathname()] = strtolower($current->getFilename());

return false;
}

return true;
};

try {
$directory = new RecursiveDirectoryIterator(
$this->scanRoot,
FilesystemIterator::SKIP_DOTS
);

$iterator = new RecursiveIteratorIterator(
new RecursiveCallbackFilterIterator($directory, $filter),
RecursiveIteratorIterator::LEAVES_ONLY,
RecursiveIteratorIterator::CATCH_GET_CHILD
);

foreach ($iterator as $file) {
if (count($this->files) >= $this->maxIndexEntries || $this->deadlineExceeded()) {
$this->indexTruncated = true;
break;
}

if (!$file instanceof SplFileInfo || !$file->isFile()) {
continue;
}

$path = $file->getPathname();
$name = strtolower($file->getFilename());
$size = @filesize($path);

$relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($path, $prefixLength));

if ($this->isExcludedPath($relative)) {
continue;
}

$this->files[] = [
'path' => $path,
'relative' => $relative,
'name' => $name,
'ext' => strtolower(pathinfo($name, PATHINFO_EXTENSION)),
'size' => $size === false ? 0 : $size
];
}
} catch (Throwable $exception) {
$this->indexTruncated = true;
}

return $this->files;
}

public function links(): array
{
$this->files();

$result = [];

foreach (array_keys($this->links) as $path) {
$result[] = [
'path' => $path,
'relative' => $this->relativePath($path)
];
}

return $result;
}

public function skippedDirectories(): array
{
$this->files();

$result = [];

foreach ($this->skippedDirectories as $path => $name) {
$result[] = [
'path' => $path,
'relative' => $this->relativePath($path),
'name' => $name
];
}

return $result;
}

public function indexTruncated(): bool
{
$this->files();

return $this->indexTruncated;
}

private function isExcludedPath(string $relative): bool
{
$relative = strtolower($relative);

foreach ($this->excludePaths as $excludePath) {
if ($relative === $excludePath || strpos($relative, $excludePath . '/') === 0) {
return true;
}
}

return false;
}

private function relativePath(string $path): string
{
$prefix = $this->scanRoot === DIRECTORY_SEPARATOR
? DIRECTORY_SEPARATOR
: $this->scanRoot . DIRECTORY_SEPARATOR;

if (strpos($path, $prefix) === 0) {
return str_replace(DIRECTORY_SEPARATOR, '/', substr($path, strlen($prefix)));
}

return basename($path);
}
}

/*** End Protection Scan Context ***/

?>