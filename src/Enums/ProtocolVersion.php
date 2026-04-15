<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Enums;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeVersionInterface;
use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;

enum ProtocolVersion: string
{
    case V1 = 'v1';
    case V2 = 'v2';

    public static function default(): self
    {
        return self::V1;
    }

    public function getSigningKeyAlgorithms(): array
    {
        return match ($this) {
            self::V1 => [SigningAlgorithm::ED25519, SigningAlgorithm::MLDSA44],
            self::V2 => [SigningAlgorithm::MLDSA44],
        };
    }

    public function getHttpSignatureAlgorithms(): array
    {
        return match ($this) {
            self::V1 => [SigningAlgorithm::ED25519, SigningAlgorithm::MLDSA44],
            self::V2 => [SigningAlgorithm::MLDSA44],
        };
    }

    public function getPublicKeyDirectoryAlgorithms(): array
    {
        return match ($this) {
            self::V1, self::V2 => [SigningAlgorithm::MLDSA44],
        };
    }

    public function isAlgorithmPermitted(SigningAlgorithm $algorithm, Purpose $purpose): bool
    {
        $allowList = match ($purpose) {
            Purpose::PUBLIC_KEY_DIRECTORY => $this->getPublicKeyDirectoryAlgorithms(),
            Purpose::HTTP_SIGNATURES => $this->getHttpSignatureAlgorithms(),
        };
        return in_array($algorithm, $allowList, true);
    }

    public function getAttributeEncryption(): AttributeVersionInterface
    {
        return match ($this) {
            self::V1 =>
                new Version1(),
            default =>
                throw new NotImplementedException("Version {$this->value} has no attribute encryption protocol"),
        };
    }

    public function getDefaultMerkleTreeHash(): string
    {
        return match ($this) {
            self::V1 => 'sha256',
            default => throw new NotImplementedException("Version {$this->value} has no hash function"),
        };
    }
}
