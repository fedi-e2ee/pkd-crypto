<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Enums;

use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SigningAlgorithm::class)]
class SigningAlgorithmTest extends TestCase
{
    public function testFromString(): void
    {
        $ed = SigningAlgorithm::fromString('ed25519');
        $ml = SigningAlgorithm::fromString('mldsa44');
        $this->assertSame('ed25519', $ed->value);
        $this->assertSame('mldsa44', $ml->value);
        $this->expectException(CryptoException::class);
        $this->expectExceptionCode(0);
        SigningAlgorithm::fromString('rsa');
    }

    public function testEd25519(): void
    {
        $alg = SigningAlgorithm::ED25519;
        $this->assertSame(32, $alg->publicKeyLength());
        $this->assertSame(64, $alg->signingKeyLength());
    }

    public function testMldsa44(): void
    {
        $alg = SigningAlgorithm::MLDSA44;
        $this->assertSame(1312, $alg->publicKeyLength());
        $this->assertSame(32, $alg->signingKeyLength());
    }
}
