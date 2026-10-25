<?php
/*
BNG 1.0.1 BackupSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Backup Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionBackupSecurity extends ProtectionPatternSecurityModule
{
public function __construct(int $maxFiles = 10000, int $maxBytes = 1048576)
{
parent::__construct($maxFiles, $maxBytes);
$this->readsContent = false;
$this->suspiciousNames = [
'~\.(?:bak|backup|old|orig|save|swp|tmp)$~i' => 'Backup or temporary file',
'#~$#' => 'Editor backup file',
'~(?:^|/)(?:backup|backups|dump|dumps|database-backup)(?:/|$)~i' => 'Backup directory or file',
'~\.(?:sql|sql\.gz|tar|tgz|tar\.gz|zip|7z|rar)$~i' => 'Archive or database dump may contain sensitive data',
'~^(?:wp-config\.php\.(?:bak|old)|configuration\.php\.(?:bak|old))$~i' => 'Potential backup of a sensitive configuration file'
];
}

public function id(): string
{
return 'backup.security';
}

protected function contextFindings(ProtectionScanContext $context): array
{
$findings = [];
foreach ($context->skippedDirectories() as $directory) {
if (!is_array($directory)) {
continue;
}
$name = $directory['name'] ?? '';
$relative = $directory['relative'] ?? '';
if (!is_string($name) || !in_array($name, ['.git', '.svn'], true)) {
continue;
}
if (!is_string($relative) || $relative === '') {
$relative = $name;
}
$findings[] = [
'type' => 'version_control_directory',
'severity' => 'review',
'path' => $relative,
'message' => 'A version control directory was found inside the scan root. Verify whether its files are publicly accessible and deny web access if the directory is inside the document root.'
];
}
return $findings;
}
}

/*** End Protection Backup Security ***/
?>