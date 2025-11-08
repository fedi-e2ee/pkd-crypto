<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use JsonSerializable;
use Override;
use ParagonIE\ConstantTime\Base64UrlSafe;

class ConsistencyProof implements JsonSerializable
{
    /**
     * @param string[] $proof
     */
    public function __construct(
        public readonly array $proof
    ) {}

    public static function fromString(string $json): ConsistencyProof
    {
        $decoded = json_decode($json);
        $proof = [];
        foreach ($decoded as $p) {
            $proof []= Base64UrlSafe::decodeNoPadding($p);
        }

        return new static(
            $proof
        );
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
