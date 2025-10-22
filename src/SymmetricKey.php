<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use ParagonIE\ConstantTime\Base64UrlSafe;

class SymmetricKey implements \JsonSerializable
{
    private string $bytes;

    public function __construct(
        #[\SensitiveParameter]
        string $bytes
    ){
        $this->bytes= $bytes;
    }

    public static function generate(): self
    {
        return new self(random_bytes(32));
    }

    public function getBytes(): string
    {
        return $this->bytes;
    }

    public function jsonSerialize(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->bytes);
    }
}
