<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;

interface ProtocolMessageInterface
{
    public function getAction(): string;
    public function toArray(): array;
    public function encrypt(AttributeKeyMap $keyMap): EncryptedProtocolMessageInterface;
}
