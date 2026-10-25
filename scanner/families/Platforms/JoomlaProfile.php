<?php
/*
BNG 1.0.1 JoomlaProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Joomla Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionJoomlaProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Joomla';
$this->markers = [
$this->file('configuration.php', 2),
$this->file('administrator/index.php', 2),
$this->dir('components', 1),
$this->dir('libraries/src', 2),
$this->dir('plugins', 1)
];
$this->uploadPaths = ['images'];
$this->configFiles = ['configuration.php'];
$this->sensitiveFiles = [
'configuration.php.bak' => 'secret',
'configuration.php.old' => 'secret',
'configuration.php~' => 'secret',
'configuration.php-dist' => 'info',
'htaccess.txt' => 'info',
'README.txt' => 'info',
'LICENSE.txt' => 'info'
];
$this->patterns = [
'joomla_legacy_jrequest' => '~\bJRequest::(?:get|getVar|getString)\s*\(~i',
'joomla_raw_input_filter' => '~->(?:get|getString)\s*\([^)]*[\x22\x27]RAW[\x22\x27]\s*\)~i',
'joomla_raw_query' => '~->setQuery\s*\([^;]{0,300}(?:\.\s*\$|\{\$)~i'
];
}

public function id(): string
{
return 'joomla';
}
}

/*** End Protection Joomla Profile ***/

?>
