<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedAddKey;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;

class AddKey implements ProtocolMessageInterface, JsonSerializable
{
    use UtilTrait;
    private string $actor;
    private DateTimeImmutable $time;
    private PublicKey $publicKey;

    public function __construct(string $actor, PublicKey $publicKey, ?DateTimeInterface $time = null)
    {
        $this->actor = $this->canonicalizeActorID($actor);
        $this->publicKey = $publicKey;
        if (is_null($time)) {
            $time = new DateTimeImmutable('NOW');
        }
        $this->time = $time;
    }

    #[Override]
    public function getAction(): string
    {
        return 'AddKey';
    }

    /**
     * ActivityPub Actor
     *
     * @api
     * @return string
     */
    public function getActor(): string
    {
        return $this->actor;
    }

    /**
     * @api
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    #[Override]
    public function toArray(): array
    {
        return [
            'actor' => $this->actor,
            'public-key' => $this->publicKey->toString(),
            'time' => $this->time->format(DateTimeInterface::ATOM),
        ];
    }

    /**
     * @return array
     */
    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    #[Override]
    public function encrypt(AttributeKeyMap $keyMap): EncryptedProtocolMessageInterface
    {
        $output = [];
        $plaintext = $this->toArray();
        foreach ($plaintext as $key => $value) {
            $symKey = $keyMap->getKey($key);
            if ($symKey) {
                $output[$key] = Base64UrlSafe::encodeUnpadded(
                    $symKey->encrypt($value)
                );
            } else {
                $output[$key] = $value;
            }
        }
        return new EncryptedAddKey($output);
    }
}
