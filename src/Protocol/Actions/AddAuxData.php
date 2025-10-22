<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedAddAuxData;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;

class AddAuxData implements ProtocolMessageInterface, JsonSerializable
{
    private string $actor;
    private string $auxType;
    private string $auxData;
    private ?string $auxId;
    private DateTimeImmutable $time;

    public function __construct(string $actor, string $auxType, string $auxData, ?string $auxId = null, ?DateTimeInterface $time = null)
    {
        $this->actor = $actor;
        $this->auxType = $auxType;
        $this->auxData = $auxData;
        $this->auxId = $auxId;
        if (is_null($time)) {
            $time = new DateTimeImmutable('NOW');
        }
        $this->time = $time;
    }

    #[Override]
    public function getAction(): string
    {
        return 'AddAuxData';
    }

    public function getActor(): string
    {
        return $this->actor;
    }

    public function getAuxType(): string
    {
        return $this->auxType;
    }

    public function getAuxData(): string
    {
        return $this->auxData;
    }

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
        if ($this->auxId) {
            $data['aux-id'] = $this->auxId;
        }
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
