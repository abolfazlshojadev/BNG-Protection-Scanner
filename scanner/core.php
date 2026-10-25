<?php
/*
BNG 1.0.1 core
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Core ***/

if (defined('PROTECTION_CORE_LOADED')) {
return;
}

if (PHP_VERSION_ID < 80000) {
throw new RuntimeException('Protection requires PHP 8.0 or newer.');
}

define('PROTECTION_CORE_LOADED', true);
define('PROTECTION_VERSION', '1.0.1');
define('PROTECTION_ROOT', __DIR__);

/*** Begin Core Dependencies ***/

$protectionCoreFiles = [
PROTECTION_ROOT . '/corephp/ScanContext.php',
PROTECTION_ROOT . '/corephp/ModuleResult.php',
PROTECTION_ROOT . '/corephp/SecurityModule.php',
PROTECTION_ROOT . '/corephp/ModuleRegistry.php',
PROTECTION_ROOT . '/corephp/Orchestrator.php',
PROTECTION_ROOT . '/corephp/SecurityKernel.php',
PROTECTION_ROOT . '/corephp/ReportWriter.php'
];

foreach ($protectionCoreFiles as $protectionCoreFile) {
if (!is_file($protectionCoreFile) || !is_readable($protectionCoreFile)) {
throw new RuntimeException('Protection core dependency is missing or unreadable: ' . basename($protectionCoreFile));
}

require_once $protectionCoreFile;
}

unset($protectionCoreFiles, $protectionCoreFile);

/*** End Core Dependencies ***/

/*** Begin Kernel Factory ***/

if (!function_exists('protection_create_kernel')) {
function protection_create_kernel(array $defaultOptions = []): ProtectionKernel
{
return new ProtectionKernel(null, null, $defaultOptions);
}
}

/*** End Kernel Factory ***/

/*** End Protection Core ***/

?>