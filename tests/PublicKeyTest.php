<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\PublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(PublicKey::class)]
class PublicKeyTest extends TestCase
{
    public static function knownAnswersMultibase(): array
    {
        return [
            ['z6MkvsDmfeVK6FxhjxxqhGvNVYWVxWdcuTa7Ghg5swZJqfFM', 'ed25519:895bv6cvVy1h85m-bt0CG2sjvHpwHb9EyTWXmEZeAKg'],
            ['u7QHz3lu_py9XLWHzmb5u3QIbayO8enAdv0TJNZeYRl4AqA', 'ed25519:895bv6cvVy1h85m-bt0CG2sjvHpwHb9EyTWXmEZeAKg'],
        ];
    }

    #[DataProvider("knownAnswersMultibase")]
    public function testMultibase(string $input, string $expected): void
    {
        $pk = PublicKey::fromMultibase($input);
        $this->assertSame($expected, $pk->toString());
        $this->assertSame($input, $pk->toMultibase($input[0] === 'z'));
    }

    public function testFromStringInvalid(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid public key: algorithm prefix required');
        PublicKey::fromString('foo');
    }

    public function testTooShort(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Public key must be 32 bytes');
        PublicKey::fromString('ed25519:foo');
    }

    public function testTooLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Public key must be 32 bytes');
        PublicKey::fromString('ed25519:' . str_repeat('A', 100));
    }

    public function testWrongAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Unknown algorithm: ed448');
        PublicKey::fromString('ed448:foo');
    }
}
