<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\PublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use FediE2EE\PKD\Crypto\SecretKey;

#[CoversClass(SecretKey::class)]
class SecretKeyTest extends TestCase
{
    public function testGetPublicKey(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit test case for fedi-e2ee/pkd-client')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

        $sk = new SecretKey($secret);
        $pk = $sk->getPublicKey();

        $this->assertInstanceOf(PublicKey::class, $pk);
        $this->assertSame($public, $pk->getBytes());
    }

    public function testPEM(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit test case for fedi-e2ee/pkd-client')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret);
        $pk = $sk->getPublicKey();

        $skPem = $sk->encodePem();
        $pkPem = $pk->encodePem();

        $expected = "-----BEGIN EC PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJCCGFPBH8jcE67DdjDPEzNaT3XMLih6iL88gDnSC3eF\n895bv6cvVy1h85m+bt0CG2sjvHpwHb9EyTWXmEZeAKg=\n-----END EC PRIVATE KEY-----";
        $this->assertSame($expected, $skPem);
        $expected = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA895bv6cvVy1h85m+bt0CG2sjvHpwHb9EyTWXmEZeAKg=\n-----END PUBLIC KEY-----";
        $this->assertSame($expected, $pkPem);

        $sk2 = SecretKey::importPem($skPem);
        $this->assertSame($sk2->getBytes(), $sk->getBytes());
        $pk2 = PublicKey::importPem($pkPem);
        $this->assertSame($pk2->getBytes(), $pk->getBytes());

        $random = SecretKey::generate();
        $decoded = SecretKey::importPem($random->encodePem());
        $this->assertSame($decoded->getBytes(), $random->getBytes());
        $this->assertSame($decoded->getPublicKey()->toString(), $random->getPublicKey()->toString());
        $this->assertSame($decoded->getPublicKey()->encodePem(), $random->getPublicKey()->encodePem());
    }

    public function importPemBadOID(): void
    {
        $this->expectException(CryptoException::class);
        SecretKey::importPem("-----BEGIN EC PRIVATE KEY-----\nMC4DAQAwBQYDK2VwBCIEIJCCGFPBH8jcE67DdjDPEzNaT3XMLih6iL88gDnSC3eF\n895bv6cvVy1h85m+bt0CG2sjvHpwHb9EyTWXmEZeAKg=\n-----END EC PRIVATE KEY-----");
    }

    public function importPublicKeyPemBadOID(): void
    {
        $this->expectException(CryptoException::class);
        PublicKey::importPem("-----BEGIN PUBLIC KEY-----\nMCpwBQYDK2VwAyEA895bv6cvVy1h85m+bt0CG2sjvHpwHb9EyTWXmEZeAKg=\n-----END PUBLIC KEY-----");
    }
}
