<?php
/*
BNG 1.0.1 DrupalProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Drupal Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionDrupalProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'Drupal';
$this->markers = [
$this->file('core/lib/Drupal.php', 3),
$this->file('web/core/lib/Drupal.php', 3),
$this->dir('sites/default', 1),
$this->file('core/includes/bootstrap.inc', 2),
$this->file('includes/bootstrap.inc', 2),
$this->file('sites/default/settings.php', 2),
$this->dir('modules', 1)
];
$this->webRoots = ['web', 'docroot'];
$this->uploadPaths = ['sites/default/files', 'web/sites/default/files', 'docroot/sites/default/files'];
$this->configFiles = ['sites/default/settings.php', 'web/sites/default/settings.php', 'docroot/sites/default/settings.php', 'sites/default/services.yml'];
$this->extensions = ['twig', 'module', 'install', 'theme', 'engine', 'profile'];
$this->sensitiveFiles = [
'sites/default/settings.php.bak' => 'secret',
'sites/default/settings.php.old' => 'secret',
'sites/default/settings.php~' => 'secret',
'sites/default/settings.local.php' => 'info',
'CHANGELOG.txt' => 'info',
'core/CHANGELOG.txt' => 'info',
'web/core/CHANGELOG.txt' => 'info',
'INSTALL.txt' => 'info'
];
$this->patterns = [
'drupal_raw_query' => '~(?:\bdb_query|->query)\s*\([^;]{0,300}(?:\.\s*\$|\{\$)~i',
'drupal_unfiltered_markup' => '~[\x22\x27]#markup[\x22\x27]\s*=>\s*\$_(?:GET|POST|REQUEST)~i',
'drupal_markup_from_request' => '~\bMarkup::create\s*\(\s*\$_(?:GET|POST|REQUEST)~i'
];
}

public function id(): string
{
return 'drupal';
}
}

/*** End Protection Drupal Profile ***/

?>
