<?php
/*
BNG 1.0.1 GenericProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Generic PHP Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionGenericProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Generic PHP';
$this->uploadPaths = ['wp-content/uploads', 'storage/app/public', 'public/uploads', 'public/upload', 'files/uploads', 'uploads', 'upload', 'files', 'media', 'images', 'sites/default/files'];
$this->configFiles = ['php.ini', '.user.ini', '.htaccess', '.env'];
$this->sensitiveFiles = [
'.env' => 'secret',
'.env.local' => 'secret',
'.env.production' => 'secret',
'.env.backup' => 'secret',
'.htpasswd' => 'secret',
'auth.json' => 'secret',
'.git/config' => 'secret',
'phpinfo.php' => 'secret',
'info.php' => 'secret',
'php_errorlog' => 'secret',
'error_log' => 'secret',
'composer.json' => 'info',
'composer.lock' => 'info'
];
}

public function id(): string
{
return 'generic';
}
}

/*** End Protection Generic PHP Profile ***/

?>
