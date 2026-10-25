<?php
/*
BNG 1.0.1 ReportWriter
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Report Writer ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionReportWriter
{
public function encode(array $report): string
{
return json_encode(
$this->sanitize($report),
JSON_PRETTY_PRINT
| JSON_UNESCAPED_SLASHES
| JSON_UNESCAPED_UNICODE
| JSON_INVALID_UTF8_SUBSTITUTE
| JSON_THROW_ON_ERROR
);
}

public function write(string $destination, array $report): bool
{
if ($destination === '') {
return false;
}

$directory = dirname($destination);

if (!is_dir($directory) || !is_writable($directory)) {
return false;
}

$realDirectory = realpath($directory);

if ($realDirectory === false) {
return false;
}

$target = $realDirectory . DIRECTORY_SEPARATOR . basename($destination);

if (is_link($target) || (file_exists($target) && !is_file($target))) {
return false;
}

try {
$json = $this->encode($report);
} catch (JsonException $exception) {
return false;
}

$tempFile = tempnam($realDirectory, '.protection-');

if ($tempFile === false) {
return false;
}

try {
$written = file_put_contents($tempFile, $json . PHP_EOL, LOCK_EX);

if ($written === false) {
return false;
}

if (!chmod($tempFile, 0600)) {
return false;
}

if (!rename($tempFile, $target)) {
return false;
}

return true;
} finally {
if (is_file($tempFile)) {
unlink($tempFile);
}
}
}

private function sanitize(mixed $value): mixed
{
if (!is_array($value)) {
if (is_string($value)) {
return substr($value, 0, 10000);
}

if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
return $value;
}

return '[unsupported value]';
}

$result = [];

foreach ($value as $key => $item) {
if (is_string($key)) {
$result[substr($key, 0, 512)] = $this->sanitize($item);
} elseif (is_int($key)) {
$result[$key] = $this->sanitize($item);
}
}

return $result;
}
}

/*** End Protection Report Writer ***/

?>