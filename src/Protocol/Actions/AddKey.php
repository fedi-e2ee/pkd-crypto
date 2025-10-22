<?php

namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use FediE2EE\PKD\Crypto\PublicKey;
use JsonSerializable;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedProtocolAddKey;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use ParagonIE\ConstantTime\Base64UrlSafe;

class AddKey implements ProtocolMessageInterface, JsonSerializable
{
    private string $actor;
    private DateTimeImmutable $time;
    private PublicKey $publicKey;

    public function __construct(string $actor, PublicKey $publicKey, ?DateTimeInterface $time = null)
    {
        $this->actor = $actor;
        $this->publicKey = $publicKey;
        if (is_null($time)) {
            $time = new DateTimeImmutable('NOW');
        }
        $this->time = $time;
    }

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
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

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
        return new EncryptedProtocolAddKey($output);
    }
}
