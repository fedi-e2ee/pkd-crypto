<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;

readonly class ParsedMessage
{
    public function __construct(
        private EncryptedProtocolMessageInterface|ProtocolMessageInterface $message,
        private AttributeKeyMap                                            $keyMap
    ) {}

    public function getMessage(): EncryptedProtocolMessageInterface|ProtocolMessageInterface
    {
        return $this->message;
    }

    public function getKeyMap(): AttributeKeyMap
    {
        return $this->keyMap;
    }
}
