<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\EncryptedActions;

use DateTimeImmutable;
use Exception;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\Actions\UndoFireproof;
use FediE2EE\PKD\Crypto\Protocol\ToStringTrait;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;
use SodiumException;

class EncryptedUndoFireproof implements EncryptedProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

    private array $encrypted;

    public function __construct(array $encrypted)
    {
        $this->encrypted = $encrypted;
    }

    #[Override]
    public function getAction(): string
    {
        return 'UndoFireproof';
    }

    #[Override]
    public function toArray(): array
    {
        return $this->encrypted;
    }

    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    #[Override]
    public function encrypt(AttributeKeyMap $keyMap): EncryptedProtocolMessageInterface
    {
        // Already encrypted
        return $this;
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    #[Override]
    public function decrypt(AttributeKeyMap $keyMap): ProtocolMessageInterface
    {
        $decrypted = [];
        foreach ($this->encrypted as $key => $value) {
            $symKey = $keyMap->getKey($key);
            if ($symKey) {
                $decrypted[$key] = $symKey->decrypt(
                    Base64UrlSafe::decodeNoPadding($value)
                );
            } else {
                $decrypted[$key] = $value;
            }
        }
        return new UndoFireproof(
            $decrypted['actor'],
            new DateTimeImmutable($decrypted['time'])
        );
    }
}
