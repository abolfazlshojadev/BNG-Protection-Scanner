<?php
/*
BNG 1.0.1 SecurityKernel
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Security Kernel ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionKernel
{
private ProtectionModuleRegistry $registry;
private ProtectionOrchestrator $orchestrator;
private bool $running = false;
private array $defaultOptions;

public function __construct(
?ProtectionModuleRegistry $registry = null,
?ProtectionOrchestrator $orchestrator = null,
array $defaultOptions = []
) {
$this->registry = $registry ?? new ProtectionModuleRegistry();
$this->orchestrator = $orchestrator ?? new ProtectionOrchestrator($this->registry);
$this->defaultOptions = $defaultOptions;
}

public function registerModule(ProtectionSecurityModule $module): void
{
if ($this->running) {
throw new LogicException('Cannot register modules during a scan.');
}

$this->registry->register($module);
}

public function run(array $options = []): array
{
if ($this->running) {
throw new LogicException('A scan is already running.');
}

$this->running = true;

try {
$context = new ProtectionScanContext(
array_replace($this->defaultOptions, $options)
);

$startedAt = microtime(true);
$runId = bin2hex(random_bytes(16));

$results = $this->orchestrator->run($context);

if ($context->indexTruncated()) {
$results['scan.context'] = (new ProtectionModuleResult(
'scan.context',
ProtectionModuleResult::STATUS_ERROR,
[
[
'type' => 'incomplete_scan',
'severity' => 'high',
'message' => 'The file index was truncated by a time or entry limit; the scan cannot be considered complete.'
]
],
['index_truncated' => true],
'Scan incomplete.'
))->toArray();
}

$summary = [
'ok' => 0,
'warning' => 0,
'failed' => 0,
'error' => 0,
'findings' => 0
];

$modulesExecuted = 0;
$registeredModules = $this->registry->all();

foreach ($results as $id => $result) {
$status = (string) ($result['status'] ?? 'error');

if (isset($summary[$status])) {
$summary[$status]++;
}

$summary['findings'] += count($result['findings'] ?? []);

if (
isset($registeredModules[$id])
&& ($result['metadata']['reason'] ?? null) !== 'skipped_time_limit'
) {
$modulesExecuted++;
}
}

return [
'version' => PROTECTION_VERSION,
'run_id' => $runId,
'started_at' => gmdate('c', (int) $startedAt),
'finished_at' => gmdate('c'),
'duration_seconds' => round(microtime(true) - $startedAt, 4),
'scan_root' => $context->scanRoot(),
'index_truncated' => $context->indexTruncated(),
'modules_registered' => $this->registry->count(),
'modules_executed' => $modulesExecuted,
'summary' => $summary,
'results' => $results
];
} finally {
$this->running = false;
}
}

public function registry(): ProtectionModuleRegistry
{
return $this->registry;
}
}

/*** End Protection Security Kernel ***/

?>