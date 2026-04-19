<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Enums;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use ParagonIE\PQCrypto\Compat;
use ValueError;

enum SigningAlgorithm: string
{
    case ED25519 = 'ed25519';
    case MLDSA44 = 'mldsa44';

    public function signingKeyLength(): int
    {
        return match ($this) {
            self::ED25519 => 64,
            self::MLDSA44 => 32,
        };
    }
    public function publicKeyLength(): int
    {
        return match ($this) {
            self::ED25519 => 32,
            self::MLDSA44 => 1312,
        };
    }

    public function signatureLength(): int
    {
        return match ($this) {
            self::ED25519 => 64,
            self::MLDSA44 => Compat::MLDSA44_SIGNATURE_BYTES,
        };
    }

    public static function fromString(string $value): static
    {
        try {
            return static::from($value);
        } catch (ValueError $error) {
            throw new CryptoException('Not a valid signing algorithm: ' . $value, 0, $error);
        }
    }
}
