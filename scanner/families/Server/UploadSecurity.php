<?php
/*
BNG 1.0.1 UploadSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Upload Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionUploadSecurity implements ProtectionSecurityModule
{
private string $rootPath;
private int $maxFiles;
private int $maxBytes;

public function __construct(string $rootPath, int $maxFiles = 2000, int $maxBytes = 5242880)
{
$realPath = realpath($rootPath);
if ($realPath === false || !is_dir($realPath) || !is_readable($realPath)) {
throw new InvalidArgumentException('Invalid upload scan root.');
}
if ($maxFiles < 1 || $maxBytes < 1) {
throw new InvalidArgumentException('Invalid scan limits.');
}
$this->rootPath = rtrim($realPath, DIRECTORY_SEPARATOR);
if ($this->rootPath === '') {
$this->rootPath = DIRECTORY_SEPARATOR;
}
$this->maxFiles = min($maxFiles, 10000);
$this->maxBytes = min($maxBytes, 10485760);
}

public function id(): string
{
return 'upload.security';
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
$scannedPaths = [];
$limitReached = false;
$timeLimitReached = false;

$scanRoot = $context->scanRoot();
$rootPrefix = $scanRoot === DIRECTORY_SEPARATOR
? DIRECTORY_SEPARATOR
: rtrim($scanRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

$uploadPaths = $context->get('upload_paths', []);

if (!is_array($uploadPaths) || $uploadPaths === []) {
return new ProtectionModuleResult(
$this->id(),
ProtectionModuleResult::STATUS_OK,
[],
[
'reason' => 'no_upload_paths_configured',
'message' => 'No upload directories are configured. Upload scanning was not applicable and no upload files were checked.',
'files_checked' => 0,
'upload_paths_checked' => 0,
'scan_limit' => min($this->maxFiles, $context->maxFiles()),
'max_bytes_per_file' => min($this->maxBytes, $context->maxBytes()),
'scan_complete' => true,
'scan_applicable' => false
]
);
}

$dangerousExtensions = [
'php', 'php3', 'php4', 'php5', 'php7', 'php8',
'phtml', 'phar', 'cgi', 'pl', 'py', 'sh', 'bash',
'asp', 'aspx', 'jsp', 'pht', 'phps', 'phpt', 'shtml', 'inc'
];

$dangerousNames = ['.htaccess', '.user.ini', 'web.config'];

try {
foreach ($uploadPaths as $uploadPath) {
if ($context->deadlineExceeded()) {
$limitReached = true;
$timeLimitReached = true;
$findings[] = [
'type' => 'scan_time_limit',
'severity' => 'warning',
'message' => 'The scan deadline was reached; remaining upload paths were not checked.'
];
break;
}

if (!is_string($uploadPath) || trim($uploadPath) === '' || strpos($uploadPath, "\0") !== false) {
$findings[] = [
'type' => 'invalid_upload_path',
'severity' => 'warning',
'message' => 'An invalid upload path was configured.'
];
continue;
}

$uploadPath = trim($uploadPath);
$isAbsolute = $uploadPath[0] === DIRECTORY_SEPARATOR
|| preg_match('/^[A-Za-z]:[\\\\\/]/', $uploadPath) === 1;

if (!$isAbsolute) {
$normalized = str_replace('\\', '/', $uploadPath);
$segments = explode('/', $normalized);
$invalid = false;
foreach ($segments as $segment) {
if ($segment === '' || $segment === '.' || $segment === '..') {
$invalid = true;
break;
}
}
if ($invalid) {
$findings[] = [
'type' => 'invalid_upload_path',
'severity' => 'warning',
'message' => 'Relative upload paths cannot contain empty or dot segments.'
];
continue;
}
$candidatePath = $scanRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $normalized);
} else {
$candidatePath = $uploadPath;
}

if (is_link($candidatePath)) {
$findings[] = [
'type' => 'invalid_upload_path',
'severity' => 'warning',
'message' => 'Symbolic-link upload directories are not scanned.'
];
continue;
}

$realPath = realpath($candidatePath);
if ($realPath === false || !is_dir($realPath) || !is_readable($realPath)) {
$findings[] = [
'type' => 'invalid_upload_path',
'severity' => 'warning',
'message' => 'An upload path is missing, unreadable, or not a directory.'
];
continue;
}

if (!$isAbsolute && ($realPath === $scanRoot || strpos($realPath, $rootPrefix) !== 0)) {
$findings[] = [
'type' => 'invalid_upload_path',
'severity' => 'warning',
'message' => 'A relative upload path resolves outside the scan root.'
];
continue;
}

if ($realPath === DIRECTORY_SEPARATOR || isset($scannedPaths[$realPath])) {
continue;
}

$scannedPaths[$realPath] = true;
$uploadPrefix = rtrim($realPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

$directory = new RecursiveDirectoryIterator($realPath, FilesystemIterator::SKIP_DOTS);
$filter = static function ($current): bool {
return $current instanceof SplFileInfo && !$current->isLink();
};
$iterator = new RecursiveIteratorIterator(
new RecursiveCallbackFilterIterator($directory, $filter),
RecursiveIteratorIterator::LEAVES_ONLY,
RecursiveIteratorIterator::CATCH_GET_CHILD
);

foreach ($iterator as $file) {
if ($context->deadlineExceeded()) {
$limitReached = true;
$timeLimitReached = true;
$findings[] = [
'type' => 'scan_time_limit',
'severity' => 'warning',
'message' => 'The scan deadline was reached; remaining upload files were not checked.'
];
break 2;
}

if ($checked >= min($this->maxFiles, $context->maxFiles())) {
$limitReached = true;
$findings[] = [
'type' => 'scan_limit',
'severity' => 'warning',
'message' => 'The upload scan file limit was reached.'
];
break 2;
}

if (!$file instanceof SplFileInfo || $file->isLink() || !$file->isFile()) {
continue;
}

$realFilePath = realpath($file->getPathname());
if ($realFilePath === false || !is_file($realFilePath) || !is_readable($realFilePath) || strpos($realFilePath, $uploadPrefix) !== 0) {
continue;
}

$checked++;
$baseName = strtolower(basename($realFilePath));
$extension = strtolower(pathinfo($realFilePath, PATHINFO_EXTENSION));
$reason = null;

if (in_array($baseName, $dangerousNames, true)) {
$reason = 'server_config_in_upload';
} elseif (in_array($extension, $dangerousExtensions, true)) {
$reason = 'executable_upload_extension';
} else {
$parts = explode('.', $baseName);
array_pop($parts);
array_shift($parts);

foreach ($parts as $part) {
if (in_array($part, $dangerousExtensions, true)) {
$reason = 'double_extension_upload';
break;
}
}
}

if ($reason === null) {
continue;
}

$size = @filesize($realFilePath);
$relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($realFilePath, strlen($uploadPrefix)));
$displayPath = $isAbsolute
? '[external-upload-root]/' . $relative
: str_replace(DIRECTORY_SEPARATOR, '/', substr($realFilePath, strlen($rootPrefix)));

$findings[] = [
'type' => $reason,
'severity' => 'high',
'file' => $displayPath,
'extension' => $extension,
'file_size' => $size === false ? null : $size,
'oversized' => $size !== false && $size > min($this->maxBytes, $context->maxBytes()),
'message' => 'Executable, script-like or server-configuration file found in a configured upload directory.'
];

if (count($findings) >= $context->maxFindings()) {
$limitReached = true;
break 2;
}
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Upload scan failed.'
);
}

return ProtectionModuleResult::fromFindings(
$this->id(),
$findings,
[
'files_checked' => $checked,
'upload_paths_checked' => count($scannedPaths),
'scan_limit' => min($this->maxFiles, $context->maxFiles()),
'max_bytes_per_file' => min($this->maxBytes, $context->maxBytes()),
'scan_limit_reached' => $limitReached,
'time_limit_reached' => $timeLimitReached,
'scan_complete' => !$limitReached,
'scan_applicable' => true
]
);
}
}

/*** End Protection Upload Security ***/

?>