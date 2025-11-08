<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

/**
 * @method toArray(): array
 */
trait ToStringTrait
{
    public function toString(): string
    {
        return json_encode(
            $this->toArray(),
            JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
