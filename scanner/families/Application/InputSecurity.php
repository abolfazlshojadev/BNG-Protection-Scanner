<?php
/*
BNG 1.0.1 InputSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Input Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionInputSecurity extends ProtectionPatternSecurityModule
{
public function __construct(int $maxFiles = 3000, int $maxBytes = 2097152)
{
parent::__construct($maxFiles, $maxBytes);

$this->patterns = [
'dynamic_include_from_request' => '~\b(?:include|include_once|require|require_once)\b\s*\(?\s*[^;]{0,100}\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
'extract_request_data' => '~\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
'weak_filtering' => '~\b(?:strip_tags|addslashes)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[~i',
'parse_str_without_result' => '~\bparse_str\s*\(\s*[^,)]+\)~i',
'unsafe_raw_filter' => '~\bFILTER_UNSAFE_RAW\b~',
'mass_assignment_unguarded' => '~\$guarded\s*=\s*\[\s*\]|\bModel::unguard\s*\(~',
'request_data_into_model' => '~\b(?:create|update|fill|forceFill|updateOrCreate|firstOrCreate)\s*\(\s*(?:\$request->all\s*\(\s*\)|request\s*\(\s*\)->all\s*\(\s*\)|\$_(?:POST|REQUEST|GET))~i'
];
$this->highIndicators = ['dynamic_include_from_request', 'extract_request_data'];
$this->reviewMessage = 'Review input validation and handling of untrusted request data.';
}

public function id(): string
{
return 'input.security';
}
}

/*** End Protection Input Security ***/

?>