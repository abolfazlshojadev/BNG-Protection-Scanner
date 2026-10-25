<?php
/*
BNG 1.0.1 LoggingSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Logging Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionLoggingSecurity extends ProtectionPatternSecurityModule
{
public function id(): string
{
return 'logging.security';
}

public function __construct(string $rootPath, int $maxFiles = 3000, int $maxBytes = 2097152)
{
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot)) {
throw new InvalidArgumentException('Invalid logging scan root.');
}

parent::__construct(
max(1, min($maxFiles, 20000)),
max(1024, min($maxBytes, 10485760))
);

$this->extensions = ['php', 'phtml', 'inc', 'ini', 'conf'];

$this->patterns = [
'password_written_to_log' => '~\b(?:error_log|syslog|file_put_contents)\s*\([^;]{0,500}\$(?:password|passwd|secret|api_key)\b~i',
'request_data_written_to_log' => '~\b(?:error_log|syslog)\s*\([^;]{0,300}\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
'debug_dump_in_application' => '~\b(?:var_dump|print_r)\s*\(\s*\$_(?:SESSION|POST|REQUEST)\b~i',
'ini_set_display_errors' => '~\bini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?(?:1|on|true)\b~i',
'verbose_error_output' => '~\b(?:display_errors|WP_DEBUG_DISPLAY)\s*["\']?\s*(?:=>|=)\s*(?:true|1|["\']1["\'])~i'
];

$this->suspiciousNames = [
'~(?:^|\.)(?:debug|error|access)\.log$~i' => 'Log file may contain sensitive operational data'
];
}
}

/*** End Protection Logging Security ***/
?>