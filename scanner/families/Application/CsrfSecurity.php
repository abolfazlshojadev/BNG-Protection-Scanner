<?php
/*
BNG 1.0.1 CsrfSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection CSRF Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

/*** Begin CSRF Security Module ***/

final class ProtectionCsrfSecurity implements ProtectionSecurityModule
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
throw new InvalidArgumentException('Invalid CSRF scan root.');
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
return 'csrf.security';
}

public function isEnabled(): bool
{
return true;
}

public function reset(): void
{
}

private function test(string $pattern, string $content, int &$errors): bool
{
$result = preg_match($pattern, $content);

if ($result === false) {
$errors++;

return false;
}

return $result === 1;
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

$extensions = ['php', 'phtml', 'inc', 'html', 'htm', 'twig', 'tpl'];

$patterns = [
'state_changing_request_handler' => '~\$_SERVER\s*\[\s*["\']REQUEST_METHOD["\']\s*\].{0,500}\b(?:POST|PUT|PATCH|DELETE)\b~is',
'form_opening_tag' => '~<form\b[^>]*>~i',
'post_form_method' => '~\bmethod\s*=\s*["\']?post\b~i',
'state_change_without_token_check' => '~\b(?:INSERT\s+INTO|UPDATE\s+[a-z_][a-z0-9_]*\s+SET|DELETE\s+FROM)\b.{0,1000}\$_(?:POST|REQUEST)\b~is',
'csrf_validation_keywords' => '~(?:csrf|xsrf|_token|wp_nonce|wp_verify_nonce|check_admin_referer|check_ajax_referer|form_key|formkey|form_token|antiforgery)~i'
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
'message' => 'Module scan time limit reached; remaining files were not checked.'
];
$limitReached = true;
break;
}

if (!in_array($entry['ext'], $extensions, true)) {
continue;
}

if ($filesChecked >= $maxFiles) {
$findings[] = [
'type' => 'scan_limit',
'severity' => 'warning',
'message' => 'CSRF scan file limit reached.'
];
$limitReached = true;
break;
}

$realPath = realpath($entry['path']);

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

$hasCsrfIndicator = $this->test($patterns['csrf_validation_keywords'], $content, $patternErrors);

$matches = [];

if ($this->test($patterns['state_changing_request_handler'], $content, $patternErrors)) {
$matches[] = 'state_changing_request_handler';
}

$hasPostForm = $this->test($patterns['form_opening_tag'], $content, $patternErrors)
&& $this->test($patterns['post_form_method'], $content, $patternErrors);

if ($hasPostForm) {
$matches[] = 'post_form_requires_csrf_review';
}

if ($this->test($patterns['state_change_without_token_check'], $content, $patternErrors)) {
$matches[] = 'state_change_uses_request_data';
}

if ($matches !== []) {
$findings[] = [
'type' => 'csrf_security_review',
'severity' => 'review',
'file' => str_replace(
DIRECTORY_SEPARATOR,
'/',
substr($realPath, strlen($prefix))
),
'indicators' => array_values(array_unique($matches)),
'csrf_keywords_found' => $hasCsrfIndicator,
'message' => 'Review state-changing requests for server-side CSRF token validation and appropriate SameSite cookie settings.'
];
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'CSRF security scan failed.'
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
'max_findings' => $maxFindings,
'scan_limit_reached' => $limitReached,
'files_skipped_too_large' => $skippedLarge,
'files_unreadable' => $unreadable,
'pattern_errors' => $patternErrors
]
);
}
}

/*** End CSRF Security Module ***/

/*** End Protection CSRF Security ***/
?>