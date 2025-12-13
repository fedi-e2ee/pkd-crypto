<?php

namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * This class abstracts a historical record returned by a PKD instance.
 */
class HistoricalRecord
{
    use UtilTrait;

    public function __construct(
        public readonly string $encryptedMessage,
        public readonly string $pkHash,
        public readonly string $signature
    ) {}

    public static function fromArray(array $data): self
    {
        if (!array_key_exists('encrypted-message', $data)) {
            throw new JsonException('Missing "encrypted-message" key');
        }
        if (!array_key_exists('publickeyhash', $data)) {
            throw new JsonException('Missing "publickeyhash" key');
        }

        return new HistoricalRecord(
            $data['encrypted-message'],
            $data['publickeyhash'],
            $data['signature'],
        );
    }

    public function serializeForMerkle(): string
    {
        return $this->preAuthEncode([
            // contentHash
            hash('sha256', $this->encryptedMessage),
            // signature
            Base64UrlSafe::decodeNoPadding($this->signature),
            // publicKeyHash
            $this->pkHash,
        ]);
    }
}
