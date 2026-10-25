<?php
/*
BNG 1.0.1 MagentoProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Magento Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionMagentoProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Magento';
$this->markers = [
$this->file('bin/magento', 3),
$this->file('app/etc/env.php', 3),
$this->file('app/etc/config.php', 2),
$this->file('app/Mage.php', 3)
];
$this->webRoots = ['pub'];
$this->uploadPaths = ['pub/media', 'media'];
$this->configFiles = ['app/etc/env.php', 'app/etc/config.php', 'app/etc/local.xml'];
$this->extensions = ['phtml'];
$this->sensitiveFiles = [
'app/etc/env.php.bak' => 'secret',
'app/etc/env.php.old' => 'secret',
'app/etc/local.xml' => 'secret',
'pub/errors/local.xml' => 'secret',
'var/log/system.log' => 'secret',
'var/log/exception.log' => 'secret',
'var/log/debug.log' => 'secret',
'auth.json' => 'secret'
];
$this->patterns = [
'magento_raw_query_with_variable' => '~->(?:query|fetchAll|fetchRow|fetchOne|fetchCol|exec)\s*\(\s*[\x22\x27][^;]{0,300}(?:\.\s*\$|\{\$)~i'
];
}

public function id(): string
{
return 'magento';
}
}

/*** End Protection Magento Profile ***/

?>
