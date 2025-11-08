<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use JsonSerializable;
use Override;
use ParagonIE\ConstantTime\Base64UrlSafe;

class InclusionProof implements JsonSerializable
{
    /**
     * @param int $index
     * @param string[] $proof
     */
    public function __construct(
        public readonly int $index,
        public readonly array $proof
    ) {}

    public static function fromString(string $json): InclusionProof
    {
        $decoded = json_decode($json);
        $proof = [];
        foreach ($decoded->proof as $p) {
            $proof []= Base64UrlSafe::decodeNoPadding($p);
        }

        return new static(
            $decoded->index,
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
        return [
            'index' => $this->index,
            'proof' => $proof,
        ];
    }
}
