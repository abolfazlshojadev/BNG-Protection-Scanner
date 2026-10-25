<?php
/*
BNG 1.0.1 ModuleRegistry
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Module Registry ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionModuleRegistry
{
private array $modules = [];

public function register(ProtectionSecurityModule $module): void
{
$id = $module->id();

if ($id === '') {
throw new InvalidArgumentException('Module ID cannot be empty.');
}

if (isset($this->modules[$id])) {
throw new LogicException('Duplicate security module ID: ' . $id);
}

$this->modules[$id] = $module;
}

public function get(string $id): ?ProtectionSecurityModule
{
return $this->modules[$id] ?? null;
}

public function all(): array
{
return $this->modules;
}

public function count(): int
{
return count($this->modules);
}
}

/*** End Protection Module Registry ***/

?>