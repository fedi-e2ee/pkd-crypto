<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use JsonSerializable;
use Override;

class RevokeKeyThirdParty implements ProtocolMessageInterface, EncryptedProtocolMessageInterface, JsonSerializable
{
    private string $revocationToken;

    public function __construct(string $revocationToken)
    {
        $this->revocationToken = $revocationToken;
    }

    #[Override]
    public function getAction(): string
    {
        return 'RevokeKeyThirdParty';
    }

    public function getRevocationToken(): string
    {
        return $this->revocationToken;
    }

    #[Override]
    public function toArray(): array
    {
        return [
            'revocation-token' => $this->revocationToken
        ];
    }

    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    #[Override]
    public function encrypt(AttributeKeyMap $keyMap): EncryptedProtocolMessageInterface
    {
        // This message has no encrypted attributes.
        return $this;
    }

    #[Override]
    public function decrypt(AttributeKeyMap $keyMap): ProtocolMessageInterface
    {
        // This message has no encrypted attributes.
        return $this;
    }
}
