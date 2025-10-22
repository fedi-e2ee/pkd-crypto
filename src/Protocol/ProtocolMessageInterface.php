<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

interface ProtocolMessageInterface
{
    public function getAction(): string;
    public function toArray(): array;
}
