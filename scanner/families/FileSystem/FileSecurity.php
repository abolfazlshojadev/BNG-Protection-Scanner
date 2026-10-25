<?php
/*
BNG 1.0.1 FileSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection File Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionFileSecurity extends ProtectionPatternSecurityModule
{
public function __construct(int $maxFiles = 5000, int $maxBytes = 2097152)
{
parent::__construct($maxFiles, $maxBytes);

$this->extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'inc'];
$this->patterns = [
'eval_call' => '~(?<![>:$\w])\beval\s*\(~i',
'shell_execution' => '~(?<![>:$\w])\b(?:shell_exec|passthru|system|exec|popen|proc_open)\s*\(~i',
'obfuscation_function' => '~\b(?:gzinflate|gzuncompress|str_rot13)\s*\(~i',
'long_base64_literal' => '~[\x22\x27][A-Za-z0-9+/=]{200,}[\x22\x27]~',
'dynamic_assert' => '~\bassert\s*\(\s*\$~i'
];
$this->highIndicators = ['eval_call', 'dynamic_assert'];
$this->reviewMessage = 'Potentially suspicious code detected; manual review is required.';
}

public function id(): string
{
return 'file.security';
}
}

/*** End Protection File Security ***/

?>