<?php
/*
BNG 1.0.1 AccessControlSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Access Control Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionAccessControlSecurity extends ProtectionPatternSecurityModule
{
public function __construct(int $maxFiles = 5000, int $maxBytes = 1048576)
{
parent::__construct($maxFiles, $maxBytes);
$this->extensions = ['php', 'phtml', 'inc', 'htaccess', 'conf'];
$this->patterns = [
'authorization_from_request_parameter' => '~\b(?:is_admin|is_authorized|has_permission)\s*\([^)]*\$_(?:GET|POST|REQUEST)\b~i',
'disabled_authentication_check' => '~\b(?:AUTH_REQUIRED|REQUIRE_AUTH|CHECK_PERMISSION)\s*=\s*(?:false|0)\b~i',
'public_file_upload_path' => '~\bmove_uploaded_file\s*\([^;]{0,500}(?:public|uploads|www)~i',
'unsafe_file_permission_change' => '~\bchmod\s*\([^;]{0,200}(?:0777|511)\b~i'
];
$this->suspiciousNames = [
'~^(?:adminer|phpinfo|test|debug|backup|old)\.php$~i' => 'Potentially sensitive utility or test file',
'~^(?:app_dev|app_test|index-test|index_dev|config_dev)\.php$~i' => 'Development front controller; must not be deployed to production'
];
}

public function id(): string
{
return 'access-control.security';
}
}

/*** End Protection Access Control Security ***/
?>