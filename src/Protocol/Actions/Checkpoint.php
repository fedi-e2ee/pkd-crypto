<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\{
    ToStringTrait,
    EncryptedProtocolMessageInterface,
    ProtocolMessageInterface,
};
use FediE2EE\PKD\Crypto\PublicKey;
use JsonSerializable;
use Override;
use function is_null;

class Checkpoint implements ProtocolMessageInterface, JsonSerializable
{
    use ToStringTrait;

    private DateTimeImmutable $time;
    private string $fromDirectory;
    private string $fromRoot;
    private PublicKey $fromPublicKey;
    private string $toDirectory;
    private string $toValidatedRoot;

    public function __construct(
        string $fromDirectory,
        string $fromRoot,
        PublicKey $fromPublicKey,
        string $toDirectory,
        string $toValidatedRoot,
        ?DateTimeInterface $time = null
    ) {
        $this->fromDirectory = $fromDirectory;
        $this->fromRoot = $fromRoot;
        $this->fromPublicKey = $fromPublicKey;
        $this->toDirectory = $toDirectory;
        $this->toValidatedRoot = $toValidatedRoot;
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
        return 'Checkpoint';
    }

    /**
     * @api
     */
    public function getTime(): DateTimeImmutable
    {
        return $this->time;
    }

    /**
     * @api
     */
    public function getFromDirectory(): string
    {
        return $this->fromDirectory;
    }

    /**
     * @api
     */
    public function getFromRoot(): string
    {
        return $this->fromRoot;
    }

    /**
     * @api
     */
    public function getFromPublicKey(): PublicKey
    {
        return $this->fromPublicKey;
    }

    /**
     * @api
     */
    public function getToDirectory(): string
    {
        return $this->toDirectory;
    }

    /**
     * @api
     */
    public function getToValidatedRoot(): string
    {
        return $this->toValidatedRoot;
    }

    #[Override]
    public function toArray(): array
    {
        $data = [
            'time' => $this->time->format(DateTimeInterface::ATOM),
            'from-directory' => $this->fromDirectory,
            'from-root' => $this->fromRoot,
            'from-public-key' => $this->fromPublicKey->toString(),
            'to-directory' => $this->toDirectory,
            'to-validated-root' => $this->toValidatedRoot,
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
    public function encrypt(AttributeKeyMap $keyMap): EncryptedProtocolMessageInterface
    {
        throw new NotImplementedException('Checkpoints are not encrypted');
    }
}
