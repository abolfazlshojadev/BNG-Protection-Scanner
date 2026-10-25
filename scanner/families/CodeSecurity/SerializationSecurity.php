<?php
/*
BNG 1.0.1 SerializationSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Serialization Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionSerializationSecurity extends ProtectionPatternSecurityModule
{
public function id(): string
{
return 'serialization.security';
}

public function __construct(string $rootPath, int $maxFiles = 3000, int $maxBytes = 2097152)
{
$realRoot = realpath($rootPath);

if ($realRoot === false || !is_dir($realRoot) || !is_readable($realRoot)) {
throw new InvalidArgumentException('Invalid serialization scan root.');
}

parent::__construct($maxFiles, $maxBytes);

$this->patterns = [
'unserialize_untrusted_input' => '~\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~i',
'unserialize_dynamic_variable' => '~\bunserialize\s*\(\s*\$[a-z_][a-z0-9_]*\s*\)~i',
'phar_metadata_usage' => '~\bphar://~i',
'unsafe_object_instantiation' => '~\b(?:unserialize|yaml_parse)\s*\(~i'
];
$this->highIndicators = ['unserialize_untrusted_input'];
}
}

/*** End Protection Serialization Security ***/
?>