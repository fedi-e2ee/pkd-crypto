<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\AttributeEncryption;

use FediE2EE\PKD\Crypto\Enums\ProtocolVersion;
use FediE2EE\PKD\Crypto\SymmetricKey;
use function array_key_exists, array_keys, count;

class AttributeKeyMap
{
    /** @var array<string, SymmetricKey> */
    private array $keys = [];
    private ProtocolVersion $version;

    public function __construct(?ProtocolVersion $version = null)
    {
        if (is_null($version)) {
            $version = ProtocolVersion::default();
        }
        $this->version = $version;
    }

    public function addKey(string $attribute, SymmetricKey $key): self
    {
        $this->keys[$attribute] = $key;
        return $this;
    }

    public function addRandomKey(string $attribute): self
    {
        $this->keys[$attribute] = SymmetricKey::generate();
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
        return count($this->keys) === 0;
    }

    public function getVersion(): ProtocolVersion
    {
        return $this->version;
    }
}
