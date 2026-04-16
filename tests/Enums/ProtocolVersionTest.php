<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Enums;

use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Enums\ProtocolVersion;
use FediE2EE\PKD\Crypto\Enums\Purpose;
use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ProtocolVersion::class)]
class ProtocolVersionTest extends TestCase
{
    public function testDefaults(): void
    {
        $version = ProtocolVersion::default();
        $this->assertInstanceOf(ProtocolVersion::class, $version);
        $this->assertSame(ProtocolVersion::V1->value, $version->value);
    }

    public function testMethodsV1(): void
    {
        $v1 = ProtocolVersion::V1;
        $this->assertSame(
            [SigningAlgorithm::ED25519, SigningAlgorithm::MLDSA44],
            $v1->getSigningKeyAlgorithms()
        );
        $this->assertSame(
            [SigningAlgorithm::ED25519, SigningAlgorithm::MLDSA44],
            $v1->getHttpSignatureAlgorithms()
        );
        $this->assertSame(
            [SigningAlgorithm::MLDSA44],
            $v1->getPublicKeyDirectoryAlgorithms()
        );
        $this->assertInstanceOf(Version1::class, $v1->getAttributeEncryption());
        $this->assertSame('sha256', $v1->getDefaultMerkleTreeHash());
    }

    public function testMethodsV2(): void
    {
        $v2 = ProtocolVersion::V2;
        $this->assertSame(
            [SigningAlgorithm::MLDSA44],
            $v2->getSigningKeyAlgorithms()
        );
        $this->assertSame(
            [SigningAlgorithm::MLDSA44],
            $v2->getHttpSignatureAlgorithms()
        );
        $this->assertSame(
            [SigningAlgorithm::MLDSA44],
            $v2->getPublicKeyDirectoryAlgorithms()
        );
    }

    public function testV2AttributeEncryptionThrows(): void
    {
        $this->expectException(NotImplementedException::class);
        ProtocolVersion::V2->getAttributeEncryption();
    }

    public function testV2MerkleTreeHashThrows(): void
    {
        $this->expectException(NotImplementedException::class);
        ProtocolVersion::V2->getDefaultMerkleTreeHash();
    }

    public function testIsAlgorithmPermittedV1(): void
    {
        $v1 = ProtocolVersion::V1;

        // PKD: only MLDSA44
        $this->assertTrue($v1->isAlgorithmPermitted(
            SigningAlgorithm::MLDSA44,
            Purpose::PUBLIC_KEY_DIRECTORY
        ));
        $this->assertFalse($v1->isAlgorithmPermitted(
            SigningAlgorithm::ED25519,
            Purpose::PUBLIC_KEY_DIRECTORY
        ));

        // HTTP Signatures: both
        $this->assertTrue($v1->isAlgorithmPermitted(
            SigningAlgorithm::ED25519,
            Purpose::HTTP_SIGNATURES
        ));
        $this->assertTrue($v1->isAlgorithmPermitted(
            SigningAlgorithm::MLDSA44,
            Purpose::HTTP_SIGNATURES
        ));
    }

    public function testIsAlgorithmPermittedV2(): void
    {
        $v2 = ProtocolVersion::V2;

        // V2: only MLDSA44 everywhere
        $this->assertTrue($v2->isAlgorithmPermitted(
            SigningAlgorithm::MLDSA44,
            Purpose::PUBLIC_KEY_DIRECTORY
        ));
        $this->assertFalse($v2->isAlgorithmPermitted(
            SigningAlgorithm::ED25519,
            Purpose::PUBLIC_KEY_DIRECTORY
        ));
        $this->assertTrue($v2->isAlgorithmPermitted(
            SigningAlgorithm::MLDSA44,
            Purpose::HTTP_SIGNATURES
        ));
        $this->assertFalse($v2->isAlgorithmPermitted(
            SigningAlgorithm::ED25519,
            Purpose::HTTP_SIGNATURES
        ));
    }
}
