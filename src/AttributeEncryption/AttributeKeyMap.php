<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\AttributeEncryption;

use FediE2EE\PKD\Crypto\SymmetricKey;

class AttributeKeyMap
{
    /** @var array<string, SymmetricKey> */
    private array $keys = [];

    public function addKey(string $attribute, SymmetricKey $key): self
    {
        $this->keys[$attribute] = $key;
        return $this;
    }

    public function getKey(string $attribute): ?SymmetricKey
    {
        return $this->keys[$attribute] ?? null;
    }

    public function getAttributes(): array
    {
        return array_keys($this->keys);
    }

    public function hasKey(string $attribute): bool
    {
        return array_key_exists($attribute, $this->keys);
    }

    public function isEmpty(): bool
    {
        return count($this->keys) !== 0;
    }
}
