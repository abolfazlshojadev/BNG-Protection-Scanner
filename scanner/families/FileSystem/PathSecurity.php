<?php
/*
BNG 1.0.1 PathSecurity
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Path Security ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionPathSecurity implements ProtectionSecurityModule
{
public function id(): string
{
return 'path.security';
}

public function isEnabled(): bool
{
return true;
}

public function reset(): void
{
}

public function execute(ProtectionScanContext $context): ProtectionModuleResult
{
$findings = [];
$maxFindings = $context->maxFindings();
$root = $context->scanRoot();
$prefix = $root === DIRECTORY_SEPARATOR ? DIRECTORY_SEPARATOR : $root . DIRECTORY_SEPARATOR;
$linksFound = 0;
$entriesChecked = 0;

try {
foreach ($context->links() as $link) {
$linksFound++;
$target = realpath($link['path']);

if ($target === false) {
$findings[] = [
'type' => 'broken_symlink',
'severity' => 'warning',
'path' => $link['relative'],
'message' => 'Symbolic link target cannot be resolved.'
];
} elseif ($root !== DIRECTORY_SEPARATOR && $target !== $root && strpos($target, $prefix) !== 0) {
$findings[] = [
'type' => 'symlink_outside_root',
'severity' => 'high',
'path' => $link['relative'],
'message' => 'Symbolic link points outside the scan root.'
];
} else {
$findings[] = [
'type' => 'symbolic_link',
'severity' => 'review',
'path' => $link['relative'],
'message' => 'Symbolic link found; verify that its target is trusted.'
];
}

if (count($findings) >= $maxFindings) {
break;
}
}

foreach ($context->files() as $entry) {
if (count($findings) >= $maxFindings || $context->deadlineExceeded()) {
break;
}

$entriesChecked++;
$relative = $entry['relative'];

if (preg_match('/[\x00-\x1f\x7f]/', $relative) === 1) {
$findings[] = [
'type' => 'control_characters_in_path',
'severity' => 'high',
'path' => $this->printable($relative),
'message' => 'File path contains control characters.'
];
continue;
}

if (preg_match('/[. ]$/', $entry['name']) === 1) {
$findings[] = [
'type' => 'trailing_dot_or_space_in_name',
'severity' => 'review',
'path' => $relative,
'message' => 'File name ends with a dot or space; verify that it is expected.'
];
continue;
}

if (substr_count($relative, '/') > 20) {
$findings[] = [
'type' => 'excessive_path_depth',
'severity' => 'review',
'path' => $relative,
'message' => 'File path is unusually deep.'
];
}
}
} catch (Throwable $exception) {
return ProtectionModuleResult::fromException(
$this->id(),
$exception,
'Path scan failed.'
);
}

$findings = array_slice($findings, 0, $maxFindings);

return ProtectionModuleResult::fromFindings(
$this->id(),
$findings,
[
'links_found' => $linksFound,
'entries_checked' => $entriesChecked
]
);
}

private function printable(string $value): string
{
return (string) preg_replace('/[^\x20-\x7e]/', '?', $value);
}
}

/*** End Protection Path Security ***/

?>