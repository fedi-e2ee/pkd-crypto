<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Enums;

use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use ParagonIE\PQCrypto\Compat;
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

    /**
     * Asserts the error code on the CryptoException is exactly 0,
     * killing Increment/DecrementInteger mutations on that literal.
     */
    public function testFromStringExceptionCode(): void
    {
        try {
            SigningAlgorithm::fromString('rsa');
            $this->fail('Expected CryptoException');
        } catch (CryptoException $e) {
            $this->assertSame(0, $e->getCode());
            $this->assertSame(
                'Not a valid signing algorithm: rsa',
                $e->getMessage()
            );
        }
    }

    public function testEd25519(): void
    {
        $alg = SigningAlgorithm::ED25519;
        $this->assertSame(32, $alg->publicKeyLength());
        $this->assertSame(64, $alg->signingKeyLength());
        $this->assertSame(64, $alg->signatureLength());
    }

    public function testMldsa44(): void
    {
        $alg = SigningAlgorithm::MLDSA44;
        $this->assertSame(1312, $alg->publicKeyLength());
        $this->assertSame(32, $alg->signingKeyLength());
        $this->assertSame(Compat::MLDSA44_SIGNATURE_BYTES, $alg->signatureLength());
    }
}
