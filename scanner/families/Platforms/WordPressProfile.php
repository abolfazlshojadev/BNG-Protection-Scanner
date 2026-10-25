<?php
/*
BNG 1.0.1 WordPressProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection WordPress Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionWordPressProfile extends ProtectionPlatformProfile
{
public function __construct()
{
$this->label = 'WordPress';
$this->markers = [
$this->file('wp-config.php', 3),
$this->dir('wp-content', 2),
$this->dir('wp-includes', 2),
$this->dir('wp-admin', 1),
$this->file('wp-load.php', 2)
];
$this->uploadPaths = ['wp-content/uploads'];
$this->configFiles = ['wp-config.php'];
$this->extensions = ['htaccess'];
$this->sensitiveFiles = [
'wp-config.php.bak' => 'secret',
'wp-config.php.old' => 'secret',
'wp-config.php.save' => 'secret',
'wp-config.php.orig' => 'secret',
'wp-config.php~' => 'secret',
'wp-content/debug.log' => 'secret',
'readme.html' => 'info',
'license.txt' => 'info'
];
$this->patterns = [
'unsafe_direct_sql' => '~\$wpdb\s*->\s*(?:query|get_results|get_row|get_var)\s*\(\s*[\x22\x27](?:SELECT|UPDATE|DELETE|INSERT)\b[^\x22\x27]*\$~i',
'unsafe_unescaped_output' => '~\becho\s+\$(?:_GET|_POST|_REQUEST)\b~i',
'disabled_file_editing' => '~\bDISALLOW_FILE_EDIT[\x22\x27]?\s*,\s*false\b~i',
'debug_display_enabled' => '~\bWP_DEBUG_DISPLAY[\x22\x27]?\s*,\s*true\b~i',
'weak_random_token' => '~\b(?:rand|mt_rand)\s*\([^)]*\).{0,150}\b(?:nonce|token|password)\b~is',
'unsafe_upload_handling' => '~\b(?:move_uploaded_file|wp_handle_upload)\s*\([^;]{0,500}\$_FILES\b~i',
'public_ajax_endpoint' => '~\badd_action\s*\(\s*[\x22\x27]wp_ajax_nopriv_~i'
];
$this->suspiciousNames = [
'~^(?:wp-config\.php\.(?:bak|old|save)|phpinfo\.php|info\.php)$~i' => 'Potentially exposed WordPress configuration or diagnostic file'
];
}

public function id(): string
{
return 'wordpress';
}
}

/*** End Protection WordPress Profile ***/

?>
