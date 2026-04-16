<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    InputException,
    JsonException,
    NetworkException,
    NotImplementedException};
use FediE2EE\PKD\Crypto\Protocol\{
    EncryptedActions\EncryptedBurnDown,
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

class BurnDown implements ProtocolMessageInterface
{
    use ToStringTrait;

    private string $actor;
    private string $operator;
    private DateTimeImmutable $time;
    private ?string $otp;

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function __construct(
        string $actor,
        string $operator,
        ?DateTimeInterface $time = null,
        ?string $otp = null
    ) {
        $this->actor = Handler::getWebFinger()->canonicalize($actor);
        $this->operator = $operator;
        if (is_null($time)) {
            $this->time = new DateTimeImmutable('NOW');
        } elseif ($time instanceof DateTimeImmutable) {
            $this->time = $time;
        } else {
            $this->time = DateTimeImmutable::createFromInterface($time);
        }
        $this->otp = $otp;
    }

    #[Override]
    public function getAction(): string
    {
        return 'BurnDown';
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
    public function getOperator(): string
    {
        return $this->operator;
    }

    /**
     * @api
     */
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
        ksort($data);
        return $data;
    }

    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @throws NotImplementedException
     */
    #[Override]
    public function encrypt(AttributeKeyMap $keyMap, string $recentMerkleRoot): EncryptedProtocolMessageInterface
    {
        throw new NotImplementedException('BurnDowns are not encrypted');
    }
}
