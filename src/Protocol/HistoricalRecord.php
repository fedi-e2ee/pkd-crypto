<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SodiumException;
use function array_key_exists, hash, sodium_hex2bin;

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

    /**
     * @throws JsonException
     */
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

    /**
     * @throws SodiumException
     */
    public function serializeForMerkle(): string
    {
        return $this->preAuthEncode([
            // contentHash
            hash('sha256', $this->encryptedMessage, true),
            // signature
            Base64UrlSafe::decodeNoPadding($this->signature),
            // publicKeyHash
            sodium_hex2bin($this->pkHash),
        ]);
    }
}
