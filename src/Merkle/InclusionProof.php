<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use JsonSerializable;
use Override;

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

    #[Override]
    public function jsonSerialize(): array
    {
        return [
            'index' => $this->index,
            'proof' => $this->proof,
        ];
    }
}
