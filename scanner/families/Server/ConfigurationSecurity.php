<?php
/*
BNG 1.0.1 ConfigurationSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Configuration Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionConfigurationSecurity implements ProtectionSecurityModule
{
private string $rootPath;

public function __construct(string $rootPath)
{
$realPath = realpath($rootPath);
if ($realPath === false || !is_dir($realPath)) {
throw new InvalidArgumentException('Invalid configuration scan root.');
}
$this->rootPath = $realPath;
}

public function id(): string
{
return 'configuration.security';
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
$configFiles = [
'php.ini',
'.user.ini',
'.htaccess',
'wp-config.php',
'configuration.php',
'settings.php',
'.env'
];

$extraConfigFiles = $context->get('config_files', []);

if (is_array($extraConfigFiles)) {
foreach ($extraConfigFiles as $extraConfigFile) {
if (
is_string($extraConfigFile)
&& $extraConfigFile !== ''
&& $extraConfigFile[0] !== '/'
&& strpos($extraConfigFile, '..') === false
&& strpos($extraConfigFile, '\\') === false
&& strpos($extraConfigFile, "\0") === false
) {
$configFiles[] = $extraConfigFile;
}
}
}

$configFiles = array_values(array_unique($configFiles));

foreach ($configFiles as $name) {
$path = $this->rootPath . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $name);
if (!is_file($path) || is_link($path) || !is_readable($path)) {
continue;
}
$size = @filesize($path);
if ($size === false || $size > $context->maxBytes()) {
continue;
}
$content = @file_get_contents($path);
if (!is_string($content)) {
continue;
}
$filesChecked++;
$indicators = [];
if ($name === '.env') {
$indicators[] = 'environment_file_present';
}
if (preg_match('/^\s*display_errors\s*=\s*(?:On|1|true)\s*$/im', $content) === 1) {
$indicators[] = 'display_errors_enabled';
}
if (preg_match('/^\s*expose_php\s*=\s*(?:On|1|true)\s*$/im', $content) === 1) {
$indicators[] = 'expose_php_enabled';
}
if (preg_match('/^\s*allow_url_include\s*=\s*(?:On|1|true)\s*$/im', $content) === 1) {
$indicators[] = 'allow_url_include_enabled';
}
if (preg_match('/^\s*APP_DEBUG\s*=\s*[\x22\x27]?(?:true|1|on)\b/im', $content) === 1) {
$indicators[] = 'app_debug_enabled';
}
if (preg_match('/^\s*APP_ENV\s*=\s*[\x22\x27]?(?:local|dev|development|test)\b/im', $content) === 1) {
$indicators[] = 'app_env_non_production';
}
if ($indicators !== []) {
$findings[] = [
'type' => 'configuration_review',
'severity' => 'review',
'file' => $name,
'indicators' => $indicators,
'message' => 'Potentially unsafe configuration; verify the effective settings.'
];
}
}

return new ProtectionModuleResult(
$this->id(),
$findings === []
? ProtectionModuleResult::STATUS_OK
: ProtectionModuleResult::STATUS_WARNING,
$findings,
[
'files_checked' => $filesChecked
]
);
}
}

/*** End Protection Configuration Security ***/
?>