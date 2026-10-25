<?php
/*
BNG 1.0.1 PlatformSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Platform Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionPlatformSecurity extends ProtectionPatternSecurityModule
{
private array $profiles = [];
private array $detectedInfo = [];
private array $activeIds = [];

public function __construct(string $rootPath, array $profiles = [], int $maxFiles = 5000, int $maxBytes = 2097152)
{
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot) || !is_readable($realRoot)) {
throw new InvalidArgumentException('Invalid platform scan root.');
}

foreach ($profiles as $profile) {
if (!$profile instanceof ProtectionPlatformProfile) {
throw new InvalidArgumentException('Invalid platform profile.');
}
}

parent::__construct(
max(1, min($maxFiles, 20000)),
max(1024, min($maxBytes, 10485760))
);

$this->profiles = array_values($profiles);
$this->extensions = ['php', 'phtml', 'inc'];
}

public function id(): string
{
return 'platform.security';
}

public function reset(): void
{
parent::reset();

$this->patterns = [];
$this->highIndicators = [];
$this->suspiciousNames = [];
$this->extensions = ['php', 'phtml', 'inc'];
$this->detectedInfo = [];
$this->activeIds = [];
}

protected function extraMetadata(): array
{
return [
'platforms_detected' => $this->detectedInfo,
'platform_profiles_active' => $this->activeIds
];
}

protected function contextFindings(ProtectionScanContext $context): array
{
$findings = [];
$active = [new ProtectionGenericProfile()];
$detector = new ProtectionPlatformDetector($this->profiles);

foreach ($detector->detect($context->scanRoot()) as $detected) {
$active[] = $detected['profile'];

$this->detectedInfo[] = [
'id' => $detected['id'],
'label' => $detected['label'],
'score' => $detected['score'],
'confidence' => $detected['confidence'],
'evidence' => $detected['evidence']
];
}

$seen = [];

foreach ($active as $profile) {
$this->activeIds[] = $profile->id();

foreach ($profile->patterns() as $name => $pattern) {
if (is_string($pattern)) {
$this->patterns[$profile->id() . '.' . $name] = $pattern;
}
}

foreach ($profile->highIndicators() as $name) {
$this->highIndicators[] = $profile->id() . '.' . $name;
}

foreach ($profile->suspiciousNames() as $pattern => $description) {
$this->suspiciousNames[(string) $pattern] = (string) $description;
}

foreach ($profile->extensions() as $extension) {
if (is_string($extension) && !in_array($extension, $this->extensions, true)) {
$this->extensions[] = strtolower($extension);
}
}

foreach ($profile->sensitiveFiles() as $path => $level) {
$path = (string) $path;

if (
$path === ''
|| $path[0] === '/'
|| strpos($path, '..') !== false
|| strpos($path, '\\') !== false
|| isset($seen[$path])
) {
continue;
}

$full = $context->scanRoot() . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $path);

if (is_link($full) || !file_exists($full)) {
continue;
}

$seen[$path] = true;
$exposure = $this->exposure($context, $profile, $path);
$isSecret = $level === 'secret';

if ($exposure === 'outside_web_root' && !$isSecret) {
continue;
}

$severity = ($isSecret && $exposure !== 'outside_web_root') ? 'high' : 'review';

$findings[] = [
'type' => 'platform_sensitive_file',
'severity' => $severity,
'platform' => $profile->id(),
'file' => $path,
'exposure' => $exposure,
'message' => $exposure === 'outside_web_root'
? 'Sensitive file found outside the platform public directory; verify that the web server document root points to that public directory.'
: 'Sensitive or diagnostic file found where it may be served publicly; remove it or deny web access.'
];
}
}

return $findings;
}

private function exposure(ProtectionScanContext $context, ProtectionPlatformProfile $profile, string $path): string
{
$option = $context->get('web_root', null);

if (is_string($option)) {
$option = trim(str_replace('\\', '/', $option), '/');

if ($option === '') {
return 'inside_web_root';
}

return ($path === $option || strpos($path, $option . '/') === 0)
? 'inside_web_root'
: 'outside_web_root';
}

$existing = [];

foreach ($profile->webRoots() as $webRoot) {
$full = $context->scanRoot() . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, (string) $webRoot);

if (is_dir($full) && !is_link($full)) {
$existing[] = (string) $webRoot;
}
}

if ($existing === []) {
return 'web_root_unknown';
}

foreach ($existing as $webRoot) {
if ($path === $webRoot || strpos($path, $webRoot . '/') === 0) {
return 'inside_web_root';
}
}

return 'outside_web_root';
}
}

/*** End Protection Platform Security ***/

?>
