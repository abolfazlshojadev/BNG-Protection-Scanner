<?php
/*
BNG 1.0.1 YiiProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Yii Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionYiiProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Yii';
$this->markers = [
$this->file('framework/yii.php', 3),
$this->dir('vendor/yiisoft', 3),
$this->file('yii', 2),
$this->file('config/web.php', 1),
$this->file('protected/config/main.php', 2)
];
$this->webRoots = ['web'];
$this->uploadPaths = ['web/uploads', 'uploads'];
$this->configFiles = ['config/web.php', 'config/db.php', 'config/web-local.php', 'protected/config/main.php', '.env'];
$this->sensitiveFiles = [
'web/index-test.php' => 'secret',
'index-test.php' => 'secret',
'runtime/logs/app.log' => 'secret',
'.env' => 'secret'
];
$this->patterns = [
'yii_debug_enabled' => '~\bdefine\s*\(\s*[\x22\x27]YII_DEBUG[\x22\x27]\s*,\s*true\s*\)~i',
'yii_dev_environment' => '~\bdefine\s*\(\s*[\x22\x27]YII_ENV[\x22\x27]\s*,\s*[\x22\x27]dev[\x22\x27]\s*\)~i',
'yii_csrf_disabled' => '~\benableCsrfValidation\s*(?:=>|=)\s*false\b~i',
'yii_empty_cookie_validation_key' => '~cookieValidationKey[\x22\x27]?\s*(?:=>|=)\s*[\x22\x27][\x22\x27]~i',
'yii_raw_sql_with_variable' => '~->(?:createCommand|andWhere|where|orderBy)\s*\(\s*[\x22\x27][^;]{0,300}(?:\.\s*\$|\{\$)~i'
];
}

public function id(): string
{
return 'yii';
}
}

/*** End Protection Yii Profile ***/

?>
