<?php
/*
BNG 1.0.1 PrestaShopProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection PrestaShop Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionPrestaShopProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'PrestaShop';
$this->markers = [
$this->file('config/config.inc.php', 3),
$this->file('classes/PrestaShopAutoload.php', 3),
$this->file('app/config/parameters.php', 3),
$this->file('config/settings.inc.php', 2),
$this->dir('modules', 1),
$this->dir('themes', 1)
];
$this->uploadPaths = ['img', 'upload', 'download'];
$this->configFiles = ['app/config/parameters.php', 'config/settings.inc.php', 'config/config.inc.php'];
$this->extensions = ['tpl'];
$this->sensitiveFiles = [
'app/config/parameters.php.bak' => 'secret',
'app/config/parameters.php.old' => 'secret',
'config/settings.inc.php.bak' => 'secret',
'var/logs/dev.log' => 'secret',
'var/logs/prod.log' => 'secret',
'install/index.php' => 'secret',
'install-dev/index.php' => 'secret'
];
$this->patterns = [
'prestashop_raw_query_with_variable' => '~\bDb::getInstance\s*\(\s*\)\s*->\s*(?:execute|executeS|getRow|getValue)\s*\(\s*[\x22\x27][^;]{0,300}(?:\.\s*\$|\{\$)~i',
'prestashop_getvalue_in_query' => '~\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^;]{0,300}Tools::getValue\s*\(~is'
];
}

public function id(): string
{
return 'prestashop';
}
}

/*** End Protection PrestaShop Profile ***/

?>
