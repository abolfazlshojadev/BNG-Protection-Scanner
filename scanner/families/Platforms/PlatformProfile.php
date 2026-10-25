<?php
/*
BNG 1.0.1 PlatformProfile
Copyright 2026 ByteNest Group, All Rights Reserved.
*/
declare(strict_types=1);

/*** Begin Protection Platform Profile ***/

if (!defined('PROTECTION_CORE_LOADED')) {
return;
}

abstract class ProtectionPlatformProfile
{
protected string $label = '';
protected int $threshold = 3;
protected array $markers = [];
protected array $webRoots = [];
protected array $uploadPaths = [];
protected array $configFiles = [];
protected array $sensitiveFiles = [];
protected array $extensions = [];
protected array $patterns = [];
protected array $highIndicators = [];
protected array $suspiciousNames = [];

abstract public function id(): string;

public function label(): string
{
return $this->label !== '' ? $this->label : $this->id();
}

public function threshold(): int
{
return $this->threshold;
}

public function markers(): array
{
return $this->markers;
}

public function webRoots(): array
{
return $this->webRoots;
}

public function uploadPaths(): array
{
return $this->uploadPaths;
}

public function configFiles(): array
{
return $this->configFiles;
}

public function sensitiveFiles(): array
{
return $this->sensitiveFiles;
}

public function extensions(): array
{
return $this->extensions;
}

public function patterns(): array
{
return $this->patterns;
}

public function highIndicators(): array
{
return $this->highIndicators;
}

public function suspiciousNames(): array
{
return $this->suspiciousNames;
}

protected function file(string $path, int $weight): array
{
return ['type' => 'file', 'path' => $path, 'weight' => $weight];
}

protected function dir(string $path, int $weight): array
{
return ['type' => 'dir', 'path' => $path, 'weight' => $weight];
}
}

/*** End Protection Platform Profile ***/

?>
