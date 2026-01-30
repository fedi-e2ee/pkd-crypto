<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\ToStringTrait;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use FediE2EE\PKD\Crypto\SecretKey;
use JsonSerializable;
use Override;

class RevokeKeyThirdParty implements ProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

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

    /**
     * @api
     */
    public static function forSecretKey(SecretKey $sk): self
    {
        return new self($sk->getRevocationToken());
    }

    /**
     * @api
     */
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

    /**
     * @throws NotImplementedException
     */
    #[Override]
    public function encrypt(AttributeKeyMap $keyMap): EncryptedProtocolMessageInterface
    {
        throw new NotImplementedException('RevokeKeyThirdParty messages are not encrypted');
    }
}
