<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedBurnDown;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\ConstantTime\Base64UrlSafe;
use JsonSerializable;
use Override;

class BurnDown implements ProtocolMessageInterface, JsonSerializable
{
    use UtilTrait;
    private string $actor;
    private string $operator;
    private DateTimeImmutable $time;
    private ?string $otp;

    public function __construct(string $actor, string $operator, ?DateTimeInterface $time = null, ?string $otp = null)
    {
        $this->actor = $this->canonicalizeActorID($actor);
        $this->operator = $operator;
        if (is_null($time)) {
            $time = new DateTimeImmutable('NOW');
        }
        $this->time = $time;
        $this->otp = $otp;
    }

    #[Override]
    public function getAction(): string
    {
        return 'BurnDown';
    }

    public function getActor(): string
    {
        return $this->actor;
    }

    public function getOperator(): string
    {
        return $this->operator;
    }

    public function getOtp(): ?string
    {
        return $this->otp;
    }

    #[Override]
    public function toArray(): array
    {
        $data = [
            'actor' => $this->actor,
            'operator' => $this->operator,
            'time' => $this->time->format(DateTimeInterface::ATOM),
        ];
        if ($this->otp) {
            $data['otp'] = $this->otp;
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
        return new EncryptedBurnDown($output);
    }
}
