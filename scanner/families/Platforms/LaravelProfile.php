<?php
/*
BNG 1.0.1 LaravelProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Laravel Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionLaravelProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Laravel';
$this->markers = [
$this->file('artisan', 3),
$this->file('bootstrap/app.php', 2),
$this->dir('app/Http', 1),
$this->file('routes/web.php', 1),
$this->file('config/app.php', 1)
];
$this->webRoots = ['public'];
$this->uploadPaths = ['storage/app/public', 'public/uploads'];
$this->configFiles = ['.env', 'config/app.php', 'config/database.php'];
$this->sensitiveFiles = [
'.env' => 'secret',
'.env.backup' => 'secret',
'.env.production' => 'secret',
'.env.local' => 'secret',
'public/.env' => 'secret',
'storage/logs/laravel.log' => 'secret',
'.env.example' => 'info',
'phpunit.xml' => 'info'
];
$this->patterns = [
'laravel_raw_sql_with_variable' => '~\b(?:DB::(?:raw|select|statement|unprepared|insert|update|delete)|whereRaw|orderByRaw|havingRaw|selectRaw|groupByRaw)\s*\((?:[^;]{0,300}(?:\.\s*\$|\{\$)|\s*\x22[^\x22;]*\$[a-z_])~i',
'laravel_debug_hardcoded' => '~[\x22\x27]debug[\x22\x27]\s*=>\s*true\b~i',
'laravel_csrf_wildcard_exception' => '~\$except\s*=\s*\[[^\]]*[\x22\x27]\*[\x22\x27]~i',
'laravel_unguarded_models' => '~\$guarded\s*=\s*\[\s*\]|\bModel::unguard\s*\(~'
];
}

public function id(): string
{
return 'laravel';
}
}

/*** End Protection Laravel Profile ***/

?>
