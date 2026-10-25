<?php
/*
BNG 1.0.1 RedirectSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Redirect Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionRedirectSecurity extends ProtectionPatternSecurityModule
{
public function __construct(string $rootPath, int $maxFiles = 3000, int $maxBytes = 2097152)
{
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot) || !is_readable($realRoot)) {
throw new InvalidArgumentException('Invalid redirect scan root.');
}

parent::__construct($maxFiles, $maxBytes);

$this->patterns = [
'request_parameter_in_redirect' => '~\bheader\s*\(\s*["\']Location:\s*["\']\s*\.\s*\$_(?:GET|POST|REQUEST)\b~i',
'redirect_to_request_value' => '~\b(?:wp_redirect|wp_safe_redirect|redirect)\s*\(\s*\$_(?:GET|POST|REQUEST)\b~i',
'unvalidated_redirect_variable' => '~\bheader\s*\(\s*["\']Location:\s*["\']\s*\.\s*\$[a-z_][a-z0-9_]*~i',
'javascript_redirect_from_location' => '~(?:window|document)\.location(?:\.href)?\s*=\s*(?:location\.(?:search|hash)|[^;\n]*\$_GET)~i'
];
}

public function id(): string
{
return 'redirect.security';
}
}

/*** End Protection Redirect Security ***/

?>