<?php
/*
BNG 1.0.1 XssSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection XSS Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionXssSecurity extends ProtectionPatternSecurityModule
{
public function __construct(int $maxFiles = 3000, int $maxBytes = 2097152)
{
parent::__construct($maxFiles, $maxBytes);

$this->extensions = ['php', 'phtml', 'inc', 'html', 'htm', 'js', 'twig', 'tpl', 'ctp'];
$this->patterns = [
'echo_request_input' => '~\b(?:echo|print)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[~i',
'short_echo_request_input' => '~<\?=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[~i',
'echo_server_value' => '~\b(?:echo|print)\s*\(?\s*\$_SERVER\s*\[\s*[\x22\x27](?:PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_REFERER)[\x22\x27]\s*\]~i',
'innerhtml_with_request_data' => '~\.innerHTML\s*=\s*[^;\n]*(?:\$_(?:GET|POST|REQUEST|COOKIE)|location\.(?:search|hash))~i',
'document_write_with_location' => '~document\.write\s*\([^;\n]*(?:location\.(?:search|hash)|document\.URL|document\.referrer)~i',
'javascript_url_with_request_data' => '~javascript\s*:[^;\n]{0,200}\$_(?:GET|POST|REQUEST)\b~i',
'template_output_request_data' => '~\{\{\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[~i',
'blade_unescaped_output' => '~\{!!\s*\$[a-z_][a-z0-9_]*~i',
'twig_raw_filter' => '~\|\s*raw\b~i',
'smarty_nofilter' => '~\|\s*nofilter\b~i',
'template_escape_disabled' => '~[\x22\x27]escape[\x22\x27]\s*=>\s*false\b~i'
];
$this->reviewMessage = 'Review output escaping and unsafe DOM operations. Pattern matches require manual verification.';
}

public function id(): string
{
return 'xss.security';
}
}

/*** End Protection XSS Security ***/

?>