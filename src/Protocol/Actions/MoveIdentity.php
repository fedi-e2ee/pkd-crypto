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
    EncryptedActions\EncryptedMoveIdentity,
    EncryptedProtocolMessageInterface,
    Handler,
    ProtocolMessageInterface,
    ToStringTrait
};
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;
use Random\RandomException;
use SodiumException;
use function is_null;

class MoveIdentity implements ProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

    private string $oldActor;
    private string $newActor;
    private DateTimeImmutable $time;

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function __construct(string $oldActor, string $newActor, ?DateTimeInterface $time = null)
    {
        $this->oldActor = Handler::getWebFinger()->canonicalize($oldActor);
        $this->newActor = Handler::getWebFinger()->canonicalize($newActor);
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
        return 'MoveIdentity';
    }

    /**
     * @api
     */
    public function getOldActor(): string
    {
        return $this->oldActor;
    }

    /**
     * @api
     */
    public function getNewActor(): string
    {
        return $this->newActor;
    }

    #[Override]
    public function toArray(): array
    {
        $data = [
            'old-actor' => $this->oldActor,
            'new-actor' => $this->newActor,
            'time' => $this->time->format(DateTimeInterface::ATOM),
        ];
        ksort($data);
        return $data;
    }

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
        return new EncryptedMoveIdentity($output);
    }
}
