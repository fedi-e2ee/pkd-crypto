<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
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

    /**f
     * @throws JsonException
     */
    public static function fromString(string $json): InclusionProof
    {
        $decoded = json_decode($json);
        if (!is_object($decoded)) {
            throw new JsonException('Invalid JSON: ' . json_last_error_msg());
        }
        $proof = [];
        foreach ($decoded->proof as $p) {
            $proof []= Base64UrlSafe::decodeNoPadding($p);
        }

        return new self(
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
