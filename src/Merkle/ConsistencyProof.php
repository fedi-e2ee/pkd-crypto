<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use JsonSerializable;
use Override;

class ConsistencyProof implements JsonSerializable
{
    /**
     * @param string[] $proof
     */
    public function __construct(
        public readonly array $proof
    ) {}

    #[Override]
    public function jsonSerialize(): array
    {
        return $this->proof;
    }
}
