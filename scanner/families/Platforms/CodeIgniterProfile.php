<?php
/*
BNG 1.0.1 CodeIgniterProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection CodeIgniter Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionCodeIgniterProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'CodeIgniter';
$this->markers = [
$this->file('system/core/CodeIgniter.php', 3),
$this->file('system/CodeIgniter.php', 3),
$this->file('spark', 2),
$this->file('app/Config/App.php', 2),
$this->file('application/config/config.php', 2),
$this->dir('application/controllers', 1)
];
$this->webRoots = ['public'];
$this->uploadPaths = ['uploads', 'public/uploads', 'writable/uploads'];
$this->configFiles = ['application/config/config.php', 'application/config/database.php', 'app/Config/App.php', 'app/Config/Database.php', '.env'];
$this->sensitiveFiles = [
'.env' => 'secret',
'env' => 'info',
'phpunit.xml.dist' => 'info'
];
$this->patterns = [
'ci_raw_query_with_variable' => '~->query\s*\([^;]{0,300}(?:\.\s*\$|\{\$)~i',
'ci_xss_filtering_disabled' => '~\$config\[[\x22\x27]global_xss_filtering[\x22\x27]\]\s*=\s*FALSE~i',
'ci_csrf_disabled' => '~\$config\[[\x22\x27]csrf_protection[\x22\x27]\]\s*=\s*FALSE~i',
'ci_empty_encryption_key' => '~\$config\[[\x22\x27]encryption_key[\x22\x27]\]\s*=\s*[\x22\x27][\x22\x27]~i'
];
}

public function id(): string
{
return 'codeigniter';
}
}

/*** End Protection CodeIgniter Profile ***/

?>
