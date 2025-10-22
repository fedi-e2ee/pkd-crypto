<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;

interface EncryptedProtocolMessageInterface extends ProtocolMessageInterface
{
    public function decrypt(AttributeKeyMap $keyMap): ProtocolMessageInterface;
}
