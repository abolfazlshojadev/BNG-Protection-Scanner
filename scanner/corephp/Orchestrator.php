<?php
/*
BNG 1.0.1 Orchestrator
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Orchestrator ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionOrchestrator
{
private ProtectionModuleRegistry $registry;

public function __construct(ProtectionModuleRegistry $registry)
{
$this->registry = $registry;
}

public function run(ProtectionScanContext $context): array
{
$results = [];

foreach ($this->registry->all() as $id => $module) {
$id = (string) $id;

if (!$module->isEnabled()) {
continue;
}

if ($context->deadlineExceeded()) {
$results[$id] = (new ProtectionModuleResult(
$id,
ProtectionModuleResult::STATUS_ERROR,
[],
['reason' => 'skipped_time_limit'],
'Module skipped: scan time limit reached.'
))->toArray();

continue;
}

$moduleStartedAt = microtime(true);

try {
$module->reset();
$result = $module->execute($context);

if (!$result instanceof ProtectionModuleResult) {
throw new UnexpectedValueException('Module returned an invalid result.');
}

$entry = $result->toArray();
} catch (Throwable $exception) {
$entry = ProtectionModuleResult::fromException(
$id,
$exception,
'Module execution failed.'
)->toArray();
}

$entry['duration_seconds'] = round(microtime(true) - $moduleStartedAt, 4);
$results[$id] = $entry;
}

return $results;
}
}

/*** End Protection Orchestrator ***/

?>