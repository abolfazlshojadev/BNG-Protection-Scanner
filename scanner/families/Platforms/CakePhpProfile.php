<?php
/*
BNG 1.0.1 CakePhpProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection CakePHP Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionCakePhpProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'CakePHP';
$this->markers = [
$this->file('bin/cake', 3),
$this->file('bin/cake.php', 3),
$this->dir('vendor/cakephp', 3),
$this->file('src/Application.php', 2),
$this->file('config/app.php', 1),
$this->file('config/app_local.php', 1),
$this->dir('app/Controller', 1),
$this->file('lib/Cake/bootstrap.php', 3)
];
$this->webRoots = ['webroot', 'app/webroot'];
$this->uploadPaths = ['webroot/files', 'webroot/uploads', 'app/webroot/files'];
$this->configFiles = ['config/app.php', 'config/app_local.php', 'config/.env', '.env'];
$this->extensions = ['ctp'];
$this->sensitiveFiles = [
'config/.env' => 'secret',
'.env' => 'secret',
'logs/error.log' => 'secret',
'logs/debug.log' => 'secret',
'config/app_local.php' => 'info'
];
$this->patterns = [
'cake_debug_enabled' => '~[\x22\x27]debug[\x22\x27]\s*=>\s*true\b~i',
'cake_default_salt' => '~__SALT__~',
'cake_raw_query_with_variable' => '~->(?:execute|query)\s*\(\s*[\x22\x27][^;]{0,300}(?:\.\s*\$|\{\$)~i',
'cake_escape_disabled' => '~[\x22\x27]escape[\x22\x27]\s*=>\s*false\b~i'
];
}

public function id(): string
{
return 'cakephp';
}
}

/*** End Protection CakePHP Profile ***/

?>
