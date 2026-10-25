<?php
/*
BNG 1.0.1 bootstrap
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Bootstrap ***/

if (!defined('PROTECTION_BOOTSTRAP_LOADED')) {
define('PROTECTION_BOOTSTRAP_LOADED', true);
}

require_once __DIR__ . '/core.php';

$protectionBaseFile = __DIR__ . '/corephp/PatternSecurityModule.php';

if (!is_file($protectionBaseFile) || !is_readable($protectionBaseFile)) {
throw new RuntimeException('Protection pattern module base is missing.');
}

require_once $protectionBaseFile;

$protectionFamilyFiles = [
'FileSystem/FileSecurity.php',
'FileSystem/PathSecurity.php',
'FileSystem/IntegritySecurity.php',
'FileSystem/BackupSecurity.php',
'Application/InputSecurity.php',
'Application/XssSecurity.php',
'Application/CsrfSecurity.php',
'Application/RedirectSecurity.php',
'Authentication/AuthenticationSecurity.php',
'Authentication/SessionSecurity.php',
'Authentication/AccessControlSecurity.php',
'Database/DatabaseSecurity.php',
'Database/SqlSecurity.php',
'Server/ConfigurationSecurity.php',
'Server/HttpSecurity.php',
'Server/RuntimeSecurity.php',
'Server/UploadSecurity.php',
'CodeSecurity/MalwareSecurity.php',
'CodeSecurity/CommandExecutionSecurity.php',
'CodeSecurity/SerializationSecurity.php',
'CodeSecurity/CryptographySecurity.php',
'Dependencies/DependencySecurity.php',
'Dependencies/SecretsSecurity.php',
'Logging/LoggingSecurity.php',
'Platforms/PlatformProfile.php',
'Platforms/PlatformDetector.php',
'Platforms/GenericProfile.php',
'Platforms/WordPressProfile.php',
'Platforms/JoomlaProfile.php',
'Platforms/DrupalProfile.php',
'Platforms/LaravelProfile.php',
'Platforms/SymfonyProfile.php',
'Platforms/CodeIgniterProfile.php',
'Platforms/YiiProfile.php',
'Platforms/CakePhpProfile.php',
'Platforms/MagentoProfile.php',
'Platforms/OpenCartProfile.php',
'Platforms/PrestaShopProfile.php',
'Platforms/PlatformSecurity.php'
];

foreach ($protectionFamilyFiles as $protectionFamilyFile) {
$protectionFamilyPath = __DIR__ . '/families/' . $protectionFamilyFile;

if (!is_file($protectionFamilyPath) || !is_readable($protectionFamilyPath)) {
throw new RuntimeException('Protection family file is missing or unreadable: ' . $protectionFamilyFile);
}

require_once $protectionFamilyPath;
}

unset($protectionBaseFile, $protectionFamilyFiles, $protectionFamilyFile, $protectionFamilyPath);

if (!function_exists('protection_platform_profiles')) {
function protection_platform_profiles(): array
{
return [
new ProtectionWordPressProfile(),
new ProtectionJoomlaProfile(),
new ProtectionDrupalProfile(),
new ProtectionLaravelProfile(),
new ProtectionSymfonyProfile(),
new ProtectionCodeIgniterProfile(),
new ProtectionYiiProfile(),
new ProtectionCakePhpProfile(),
new ProtectionMagentoProfile(),
new ProtectionOpenCartProfile(),
new ProtectionPrestaShopProfile()
];
}
}

if (!function_exists('protection_create_scanner')) {
function protection_create_scanner(
string $scanRoot,
array $integrityBaseline = [],
array $options = []
): ProtectionKernel {
$realRoot = realpath($scanRoot);

if ($realRoot === false || !is_dir($realRoot) || !is_readable($realRoot)) {
throw new InvalidArgumentException('Invalid Protection scan root.');
}

$options['scan_root'] = $realRoot;

if (!isset($options['exclude_paths']) || !is_array($options['exclude_paths'])) {
$options['exclude_paths'] = [];
$protectionReal = realpath(PROTECTION_ROOT);
$protectionPrefix = rtrim($realRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

if ($protectionReal !== false && strpos($protectionReal, $protectionPrefix) === 0) {
$options['exclude_paths'][] = str_replace(DIRECTORY_SEPARATOR, '/', substr($protectionReal, strlen($protectionPrefix)));
}
}

$platformProfiles = protection_platform_profiles();
$platformDetector = new ProtectionPlatformDetector($platformProfiles);
$activeProfiles = [new ProtectionGenericProfile()];

foreach ($platformDetector->detect($realRoot) as $detectedPlatform) {
$activeProfiles[] = $detectedPlatform['profile'];
}

if (!isset($options['config_files']) || !is_array($options['config_files'])) {
$options['config_files'] = [];

foreach ($activeProfiles as $activeProfile) {
foreach ($activeProfile->configFiles() as $configFile) {
$options['config_files'][] = $configFile;
}
}

$options['config_files'] = array_values(array_unique($options['config_files']));
}

if (
!isset($options['upload_paths'])
|| !is_array($options['upload_paths'])
|| $options['upload_paths'] === []
) {
$uploadCandidates = [];

foreach ($activeProfiles as $activeProfile) {
foreach ($activeProfile->uploadPaths() as $uploadCandidate) {
$uploadCandidates[] = $uploadCandidate;
}
}

$uploadCandidates = array_values(array_unique($uploadCandidates));

$detectedUploadPaths = [];

foreach ($uploadCandidates as $relativePath) {
$candidate = $realRoot . DIRECTORY_SEPARATOR
. str_replace('/', DIRECTORY_SEPARATOR, $relativePath);

if (
!is_dir($candidate)
|| is_link($candidate)
|| !is_readable($candidate)
) {
continue;
}

$resolvedCandidate = realpath($candidate);
$rootPrefix = rtrim($realRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

if (
$resolvedCandidate === false
|| $resolvedCandidate === $realRoot
|| strpos($resolvedCandidate, $rootPrefix) !== 0
) {
continue;
}

$detectedUploadPaths[] = $relativePath;
}

$options['upload_paths'] = array_values(array_unique($detectedUploadPaths));
}

$kernel = protection_create_kernel($options);

$modules = [
new ProtectionFileSecurity(),
new ProtectionPathSecurity(),
new ProtectionIntegritySecurity($integrityBaseline),
new ProtectionBackupSecurity(),
new ProtectionInputSecurity(),
new ProtectionXssSecurity(),
new ProtectionCsrfSecurity($realRoot),
new ProtectionRedirectSecurity($realRoot),
new ProtectionAuthenticationSecurity($realRoot),
new ProtectionSessionSecurity($realRoot),
new ProtectionAccessControlSecurity(),
new ProtectionDatabaseSecurity($realRoot),
new ProtectionSqlSecurity($realRoot),
new ProtectionConfigurationSecurity($realRoot),
new ProtectionHttpSecurity($realRoot),
new ProtectionRuntimeSecurity(),
new ProtectionUploadSecurity($realRoot),
new ProtectionMalwareSecurity($realRoot),
new ProtectionCommandExecutionSecurity($realRoot),
new ProtectionSerializationSecurity($realRoot),
new ProtectionCryptographySecurity($realRoot),
new ProtectionDependencySecurity($realRoot),
new ProtectionSecretsSecurity($realRoot),
new ProtectionLoggingSecurity($realRoot),
new ProtectionPlatformSecurity($realRoot, $platformProfiles)
];

foreach ($modules as $module) {
$kernel->registerModule($module);
}

return $kernel;
}
}

/*** End Protection Bootstrap ***/

?>