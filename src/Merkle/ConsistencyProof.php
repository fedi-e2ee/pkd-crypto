<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use JsonSerializable;
use Override;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function is_array, json_decode, json_last_error_msg;

class ConsistencyProof implements JsonSerializable
{
    /**
     * @param string[] $proof
     */
    public function __construct(
        public readonly array $proof
    ) {}

    /**
     * @throws JsonException
     */
    public static function fromString(string $json): ConsistencyProof
    {
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            throw new JsonException('Invalid JSON: ' . json_last_error_msg());
        }
        $proof = [];
        foreach ($decoded as $p) {
            $proof []= Base64UrlSafe::decodeNoPadding($p);
        }

        return new self($proof);
    }

    #[Override]
    public function jsonSerialize(): array
    {
        $proof = [];
        foreach ($this->proof as $p) {
            $proof []= Base64UrlSafe::encodeUnpadded($p);
        }
        return $proof;
    }
}
