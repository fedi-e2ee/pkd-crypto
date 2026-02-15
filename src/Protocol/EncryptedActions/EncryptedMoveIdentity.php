<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\EncryptedActions;

use DateTimeImmutable;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use GuzzleHttp\Exception\GuzzleException;
use FediE2EE\PKD\Crypto\Exceptions\{
    InputException,
    JsonException,
    NetworkException
};
use FediE2EE\PKD\Crypto\Protocol\{
    Actions\MoveIdentity,
    EncryptedProtocolMessageInterface,
    ProtocolMessageInterface,
    ToStringTrait
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;
use SodiumException;

class EncryptedMoveIdentity implements EncryptedProtocolMessageInterface, JsonSerializable
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
        return 'MoveIdentity';
    }

    #[Override]
    public function toArray(): array
    {
        $data = $this->encrypted;
        ksort($data);
        return $data;
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
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
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
        return new MoveIdentity(
            $decrypted['old-actor'],
            $decrypted['new-actor'],
            new DateTimeImmutable($decrypted['time'])
        );
    }
}
