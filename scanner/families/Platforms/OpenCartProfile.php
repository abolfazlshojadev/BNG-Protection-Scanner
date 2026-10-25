<?php
/*
BNG 1.0.1 OpenCartProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection OpenCart Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionOpenCartProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'OpenCart';
$this->markers = [
$this->file('system/startup.php', 2),
$this->dir('catalog/controller', 2),
$this->dir('admin/controller', 1),
$this->file('config.php', 1),
$this->dir('system/library', 1),
$this->file('system/framework.php', 2)
];
$this->uploadPaths = ['image', 'system/storage/upload', 'storage/upload'];
$this->configFiles = ['config.php', 'admin/config.php'];
$this->sensitiveFiles = [
'config.php.bak' => 'secret',
'admin/config.php.bak' => 'secret',
'system/storage/logs/error.log' => 'secret',
'storage/logs/error.log' => 'secret',
'system/logs/error.txt' => 'secret'
];
$this->patterns = [
'opencart_raw_query_with_variable' => '~->db->query\s*\(\s*[\x22\x27][^;]{0,300}(?:\.\s*\$|\{\$)~i'
];
}

public function id(): string
{
return 'opencart';
}
}

/*** End Protection OpenCart Profile ***/

?>
