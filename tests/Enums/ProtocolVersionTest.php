<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Enums;

use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Enums\ProtocolVersion;
use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;
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
        $this->assertSame([SigningAlgorithm::ED25519, SigningAlgorithm::MLDSA44], $v1->getSigningKeyAlgorithms());
        $this->assertSame([SigningAlgorithm::ED25519, SigningAlgorithm::MLDSA44], $v1->getHttpSignatureAlgorithms());
        $this->assertSame([SigningAlgorithm::MLDSA44], $v1->getPublicKeyDirectoryAlgorithms());
        $this->assertInstanceOf(Version1::class, $v1->getAttributeEncryption());
        $this->assertSame('sha256', $v1->getDefaultMerkleTreeHash());
    }
}
