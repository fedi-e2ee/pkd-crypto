<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol\Actions;

use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\ProtocolMessageInterface;
use FediE2EE\PKD\Crypto\PublicKey;
use JsonSerializable;
use Override;

class Checkpoint implements ProtocolMessageInterface, EncryptedProtocolMessageInterface, JsonSerializable
{
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
            $time = new DateTimeImmutable('NOW');
        }
        $this->time = $time;
    }

    #[Override]
    public function getAction(): string
    {
        return 'Checkpoint';
    }

    public function getTime(): DateTimeImmutable
    {
        return $this->time;
    }

    public function getFromDirectory(): string
    {
        return $this->fromDirectory;
    }

    public function getFromRoot(): string
    {
        return $this->fromRoot;
    }

    public function getFromPublicKey(): PublicKey
    {
        return $this->fromPublicKey;
    }

    public function getToDirectory(): string
    {
        return $this->toDirectory;
    }

    public function getToValidatedRoot(): string
    {
        return $this->toValidatedRoot;
    }

    #[Override]
    public function toArray(): array
    {
        return [
            'time' => $this->time->format(DateTimeInterface::ATOM),
            'from-directory' => $this->fromDirectory,
            'from-root' => $this->fromRoot,
            'from-public-key' => $this->fromPublicKey->toString(),
            'to-directory' => $this->toDirectory,
            'to-validated-root' => $this->toValidatedRoot,
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
        // This message has no encrypted attributes.
        return $this;
    }

    #[Override]
    public function decrypt(AttributeKeyMap $keyMap): ProtocolMessageInterface
    {
        // This message has no encrypted attributes.
        return $this;
    }
}
