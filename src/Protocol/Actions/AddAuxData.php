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
    Handler,
    ToStringTrait,
    EncryptedActions\EncryptedAddAuxData,
    EncryptedProtocolMessageInterface,
    ProtocolMessageInterface
};
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;
use Random\RandomException;
use SodiumException;
use function is_null;

class AddAuxData implements ProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

    private string $actor;
    private string $auxType;
    private string $auxData;
    private ?string $auxId;
    private DateTimeImmutable $time;

    /**
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws GuzzleException
     */
    public function __construct(
        string $actor,
        string $auxType,
        string $auxData,
        ?string $auxId = null,
        ?DateTimeInterface $time = null
    ) {
        $this->actor = Handler::getWebFinger()->canonicalize($actor);
        $this->auxType = $auxType;
        $this->auxData = $auxData;
        $this->auxId = $auxId;
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
        return 'AddAuxData';
    }

    /**
     * @api
     */
    public function getActor(): string
    {
        return $this->actor;
    }

    /**
     * @api
     */
    public function getAuxType(): string
    {
        return $this->auxType;
    }

    /**
     * @api
     */
    public function getAuxData(): string
    {
        return $this->auxData;
    }

    /**
     * @api
     */
    public function getAuxId(): ?string
    {
        return $this->auxId;
    }

    #[Override]
    public function toArray(): array
    {
        $data = [
            'actor' => $this->actor,
            'aux-type' => $this->auxType,
            'aux-data' => $this->auxData,
            'time' => $this->time->format(DateTimeInterface::ATOM),
        ];
        if ($this->auxId !== null) {
            $data['aux-id'] = $this->auxId;
        }
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
        return new EncryptedAddAuxData($output);
    }
}
