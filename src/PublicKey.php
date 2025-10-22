<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use SensitiveParameter;

final class PublicKey
{
    private string $bytes;
    private string $algo;

    public function __construct(
        #[SensitiveParameter]
        string $bytes,
        string $algo = 'ed25519'
    ) {
        $this->bytes = $bytes;
        $this->algo = $algo;
    }

    public function getBytes(): string
    {
        return $this->bytes;
    }

    public function getAlgo(): string
    {
        return $this->algo;
    }
}
