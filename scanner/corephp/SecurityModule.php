<?php
/*
BNG 1.0.1 SecurityModule
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Security Module ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

interface ProtectionSecurityModule
{
public function id(): string;

public function isEnabled(): bool;

public function execute(ProtectionScanContext $context): ProtectionModuleResult;

public function reset(): void;
}

/*** End Protection Security Module ***/

?>