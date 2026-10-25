<?php
/*
BNG 1.0.1 ModuleResult
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Module Result ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

final class ProtectionModuleResult
{
public const STATUS_OK = 'ok';
public const STATUS_WARNING = 'warning';
public const STATUS_FAILED = 'failed';
public const STATUS_ERROR = 'error';

private string $moduleId;
private string $status;
private array $findings;
private array $metadata;
private ?string $message;

public function __construct(
string $moduleId,
string $status = self::STATUS_OK,
array $findings = [],
array $metadata = [],
?string $message = null
) {
if ($moduleId === '') {
throw new InvalidArgumentException('Module ID cannot be empty.');
}

$allowedStatuses = [
self::STATUS_OK,
self::STATUS_WARNING,
self::STATUS_FAILED,
self::STATUS_ERROR
];

if (!in_array($status, $allowedStatuses, true)) {
throw new InvalidArgumentException('Invalid module result status.');
}

if ($status !== self::STATUS_ERROR) {
foreach ($findings as $finding) {
if (is_array($finding) && ($finding['severity'] ?? null) === 'high') {
$status = self::STATUS_FAILED;
break;
}
}
}

$this->moduleId = $moduleId;
$this->status = $status;
$this->findings = $findings;
$this->metadata = $metadata;
$this->message = $message;
}

public static function fromFindings(
string $moduleId,
array $findings,
array $metadata = [],
?string $message = null
): self {
$status = self::STATUS_OK;

foreach ($findings as $finding) {
$severity = is_array($finding) ? ($finding['severity'] ?? '') : '';

if ($severity === 'high') {
$status = self::STATUS_FAILED;
break;
}

$status = self::STATUS_WARNING;
}

return new self($moduleId, $status, $findings, $metadata, $message);
}

public static function fromException(
string $moduleId,
Throwable $exception,
string $reason
): self {
return new self(
$moduleId,
self::STATUS_ERROR,
[],
[
'reason' => $reason,
'exception' => get_class($exception),
'error_detail' => substr($exception->getMessage(), 0, 300)
],
$reason
);
}

public function status(): string
{
return $this->status;
}

public function isSuccessful(): bool
{
return $this->status === self::STATUS_OK;
}

public function hasFindings(): bool
{
return $this->findings !== [];
}

public function toArray(): array
{
return [
'module_id' => $this->moduleId,
'status' => $this->status,
'findings' => $this->findings,
'metadata' => $this->metadata,
'message' => $this->message
];
}
}

/*** End Protection Module Result ***/

?>