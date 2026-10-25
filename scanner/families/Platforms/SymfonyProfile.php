<?php
/*
BNG 1.0.1 SymfonyProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Symfony Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionSymfonyProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Symfony';
$this->markers = [
$this->file('bin/console', 3),
$this->file('symfony.lock', 2),
$this->file('config/bundles.php', 2),
$this->file('src/Kernel.php', 2),
$this->dir('config/packages', 1)
];
$this->webRoots = ['public', 'web'];
$this->uploadPaths = ['public/uploads', 'public/upload', 'var/uploads', 'web/uploads'];
$this->configFiles = ['.env', '.env.local', '.env.prod'];
$this->extensions = ['twig', 'yaml', 'yml'];
$this->sensitiveFiles = [
'.env' => 'secret',
'.env.local' => 'secret',
'.env.local.php' => 'secret',
'.env.prod' => 'secret',
'var/log/dev.log' => 'secret',
'var/log/prod.log' => 'secret',
'var/log/test.log' => 'secret',
'public/app_dev.php' => 'secret',
'web/app_dev.php' => 'secret',
'web/config.php' => 'secret',
'symfony.lock' => 'info'
];
$this->patterns = [
'symfony_raw_query_with_variable' => '~->(?:createQuery|executeQuery|executeStatement|executeUpdate|fetchAll|fetchAssociative|prepare)\s*\([^;]{0,300}(?:\.\s*\$|\{\$)~i',
'symfony_csrf_disabled' => '~[\x22\x27]csrf_protection[\x22\x27]\s*=>\s*false\b|csrf_protection\s*:\s*false\b~i',
'twig_autoescape_disabled' => '~\{%\s*autoescape\s+(?:false|[\x22\x27]false[\x22\x27])\s*%\}|autoescape\s*(?:=>|:)\s*(?:false|[\x22\x27]false[\x22\x27])\b~i'
];
}

public function id(): string
{
return 'symfony';
}
}

/*** End Protection Symfony Profile ***/

?>
