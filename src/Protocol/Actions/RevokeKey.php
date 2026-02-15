<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    InputException,
    JsonException,
    NetworkException
};
use FediE2EE\PKD\Crypto\Protocol\{
    EncryptedActions\EncryptedRevokeKey,
    EncryptedProtocolMessageInterface,
    Handler,
    ProtocolMessageInterface,
    ToStringTrait
};
use FediE2EE\PKD\Crypto\PublicKey;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;
use Random\RandomException;
use SodiumException;
use function is_null;

class RevokeKey implements ProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

    private string $actor;
    private DateTimeImmutable $time;
    private PublicKey $publicKey;

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function __construct(string $actor, PublicKey $publicKey, ?DateTimeInterface $time = null)
    {
        $this->actor = Handler::getWebFinger()->canonicalize($actor);
        $this->publicKey = $publicKey;
        if (is_null($time)) {
            $this->time = new DateTimeImmutable('NOW');
        } elseif ($time instanceof DateTimeImmutable) {
            $this->time = $time;
        } else {
            $this->time = DateTimeImmutable::createFromInterface($time);
        }
    }

    #[Override]
    public function getAction(): string
    {
        return 'RevokeKey';
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
        $data = [
            'actor' => $this->actor,
            'public-key' => $this->publicKey->toString(),
            'time' => $this->time->format(DateTimeInterface::ATOM),
        ];
        ksort($data);
        return $data;
    }

    /**
     * @return array
     */
    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @throws RandomException
     * @throws SodiumException
     */
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
        return new EncryptedRevokeKey($output);
    }
}
