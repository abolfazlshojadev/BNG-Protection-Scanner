<?php
/*
BNG 1.0.1 PlatformDetector
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Platform Detector ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionPlatformDetector
{
private array $profiles = [];

public function __construct(array $profiles)
{
foreach ($profiles as $profile) {
if (!$profile instanceof ProtectionPlatformProfile) {
throw new InvalidArgumentException('Invalid platform profile.');
}

$id = $profile->id();

if ($id === '' || isset($this->profiles[$id])) {
throw new InvalidArgumentException('Platform profile ID is empty or duplicated.');
}

$this->profiles[$id] = $profile;
}
}

public function detect(string $root): array
{
$realRoot = realpath($root);

if ($realRoot === false || !is_dir($realRoot)) {
return [];
}

$detected = [];

foreach ($this->profiles as $id => $profile) {
$score = 0;
$evidence = [];

foreach ($profile->markers() as $marker) {
$relative = $marker['path'] ?? null;
$type = $marker['type'] ?? null;
$weight = $marker['weight'] ?? 0;

if (
!is_string($relative)
|| $relative === ''
|| $relative[0] === '/'
|| strpos($relative, '..') !== false
|| strpos($relative, "\0") !== false
|| !in_array($type, ['file', 'dir'], true)
|| !is_int($weight)
) {
continue;
}

$path = $realRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);

if (is_link($path)) {
continue;
}

$present = $type === 'dir' ? is_dir($path) : is_file($path);

if ($present) {
$score += $weight;
$evidence[] = $relative;
}
}

if ($score < $profile->threshold()) {
continue;
}

$detected[] = [
'id' => (string) $id,
'label' => $profile->label(),
'score' => $score,
'confidence' => $score >= $profile->threshold() * 2 ? 'high' : 'medium',
'evidence' => $evidence,
'profile' => $profile
];
}

usort(
$detected,
static function (array $a, array $b): int {
return $b['score'] <=> $a['score'];
}
);

return $detected;
}
}

/*** End Protection Platform Detector ***/

?>
