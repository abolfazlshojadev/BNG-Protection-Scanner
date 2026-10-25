<?php
/*
BNG 1.0.1 RuntimeSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Runtime Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionRuntimeSecurity extends ProtectionPatternSecurityModule
{
public function __construct(int $maxFiles = 3000, int $maxBytes = 1048576)
{
parent::__construct($maxFiles, $maxBytes);
$this->extensions = ['php', 'phtml', 'inc', 'ini', 'conf', 'htaccess'];
$this->patterns = [
'display_errors_enabled' => '~\b(?:display_errors|display_startup_errors)\s*=\s*(?:On|1|true)\b~i',
'remote_file_inclusion_enabled' => '~\ballow_url_include\s*=\s*(?:On|1|true)\b~i',
'unsafe_runtime_ini_override' => '~\bini_set\s*\(\s*["\'](?:display_errors|allow_url_include)["\']\s*,\s*["\']?(?:1|On|true)["\']?\s*\)~i',
'disabled_security_functions_override' => '~\bdisable_functions\s*=\s*["\']?\s*(?:$|[,;])~im',
'debug_mode_enabled' => '~\b(?:APP_DEBUG|DEBUG|WP_DEBUG)\s*["\']?\s*(?:=>|=|:)\s*(?:true|1|["\']true["\'])~i'
];
}

public function id(): string
{
return 'runtime.security';
}
}

/*** End Protection Runtime Security ***/
?>