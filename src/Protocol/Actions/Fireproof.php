<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NetworkException;
use FediE2EE\PKD\Crypto\Protocol\Handler;
use FediE2EE\PKD\Crypto\Protocol\ToStringTrait;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedFireproof;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;

class Fireproof implements ProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

    private string $actor;
    private DateTimeImmutable $time;

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function __construct(string $actor, ?DateTimeInterface $time = null)
    {
        $this->actor = Handler::getWebFinger()->canonicalize($actor);
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
        return 'Fireproof';
    }

    /**
     * @api
     */
    public function getActor(): string
    {
        return $this->actor;
    }

    #[Override]
    public function toArray(): array
    {
        return [
            'actor' => $this->actor,
            'time' => $this->time->format(DateTimeInterface::ATOM),
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
        return new EncryptedFireproof($output);
    }
}
