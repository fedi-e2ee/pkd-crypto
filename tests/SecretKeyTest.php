<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\PublicKey;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use FediE2EE\PKD\Crypto\SecretKey;
use Random\RandomException;
use SodiumException;

#[CoversClass(SecretKey::class)]
class SecretKeyTest extends TestCase
{
    use ExtraneousDataProviderTrait;

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public function testGetPublicKeyEd25519(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit test case for fedi-e2ee/pkd-client')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

        $sk = new SecretKey($secret, SigningAlgorithm::ED25519);
        $pk = $sk->getPublicKey();

        $this->assertInstanceOf(PublicKey::class, $pk);
        $this->assertSame($public, $pk->getBytes());
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("signingAlgorithmProvider")]
    public function testGetPublicKeyRoundTrip(SigningAlgorithm $alg): void
    {
        $sk = SecretKey::generate($alg);
        $pk = $sk->getPublicKey();

        $this->assertInstanceOf(PublicKey::class, $pk);
        $this->assertSame($alg, $pk->getAlgo());
        $this->assertSame($alg->publicKeyLength(), strlen($pk->getBytes()));
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public function testPEMEd25519KnownAnswer(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit test case for fedi-e2ee/pkd-client')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret, SigningAlgorithm::ED25519);
        $pk = $sk->getPublicKey();

        $skPem = $sk->encodePem();
        $pkPem = $pk->encodePem();

        $expected = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJCCGFPBH8jcE67DdjDPEzNaT3XMLih6iL88gDnSC3eF\n-----END PRIVATE KEY-----";
        $this->assertSame($expected, $skPem);
        $expected = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA895bv6cvVy1h85m+bt0CG2sjvHpwHb9EyTWXmEZeAKg=\n-----END PUBLIC KEY-----";
        $this->assertSame($expected, $pkPem);

        $sk2 = SecretKey::importPem($skPem, SigningAlgorithm::ED25519);
        $this->assertSame($sk2->getBytes(), $sk->getBytes());
        $pk2 = PublicKey::importPem($pkPem, SigningAlgorithm::ED25519);
        $this->assertSame($pk2->getBytes(), $pk->getBytes());
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("signingAlgorithmProvider")]
    public function testPEMRoundTrip(SigningAlgorithm $alg): void
    {
        $random = SecretKey::generate($alg);
        $decoded = SecretKey::importPem($random->encodePem(), $alg);
        $this->assertSame($decoded->getBytes(), $random->getBytes());
        $this->assertSame($decoded->getPublicKey()->toString(), $random->getPublicKey()->toString());
        $this->assertSame($decoded->getPublicKey()->encodePem(), $random->getPublicKey()->encodePem());
    }

    /**
     * @throws SodiumException
     */
    public function testImportPemBadOID(): void
    {
        $this->expectException(CryptoException::class);
        SecretKey::importPem("-----BEGIN PRIVATE KEY-----\nMC4DAQAwBQYDK2VwBCIEIJCCGFPBH8jcE67DdjDPEzNaT3XMLih6iL88gDnSC3eF\n-----END PRIVATE KEY-----");
    }

    public function testImportPublicKeyPemBadOID(): void
    {
        $this->expectException(CryptoException::class);
        PublicKey::importPem("-----BEGIN PUBLIC KEY-----\nMCpwBQYDK2VwAyEA895bv6cvVy1h85m+bt0CG2sjvHpwHb9EyTWXmEZeAKg=\n-----END PUBLIC KEY-----");
    }

    /**
     * @throws RandomException
     */
    public function testTooShort(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Secret key must be 64 bytes');
        new SecretKey(random_bytes(32), SigningAlgorithm::ED25519);
    }

    /**
     * @throws RandomException
     */
    public function testTooLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Secret key must be 64 bytes');
        new SecretKey(random_bytes(65), SigningAlgorithm::ED25519);
    }

    /**
     * @throws RandomException
     */
    public function testWrongAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Not a valid signing algorithm: ed448');
        new SecretKey('foo', 'ed448');
    }

    public function testMldsa44(): void
    {
        $sk = SecretKey::generate(SigningAlgorithm::MLDSA44);
        $this->assertSame('mldsa44', $sk->getAlgo()->value);
        $this->assertSame(32, strlen($sk->getBytes()));

        // Test with deterministic inputs
        $sk2 = new SecretKey(hash('sha256', 'unit testing', true), 'mldsa44');
        $expected = '-----BEGIN PRIVATE KEY-----' . "\n" .
            'MDQCAQAwCwYJYIZIAWUDBAMRBCKAIMmVWL/mRG+3IQddHi3yL1dfyQVXr3h07ZdW' . "\n" .
            '0FphW5SC' . "\n" .
            '-----END PRIVATE KEY-----';
        $this->assertSame($expected, $sk2->encodePem());
        $sk2p = SecretKey::importPem($expected, 'mldsa44');
        $this->assertSame($sk2->getBytes(), $sk2p->getBytes());
        $this->assertSame($sk2->getAlgo(), $sk2p->getAlgo());
        $pk2 = $sk2->getPublicKey();
        $this->assertSame($sk2->getAlgo(), $pk2->getAlgo());
        $this->assertSame(
            '32ec4cb94fd7dfade21c14420d0009d6974f6a488a4449322b3a2019f78b674c',
            hash('sha256', $pk2->getBytes())
        );
        $this->assertSame(
            '28e4b0f9dc0d5ed51167e8e6edb5c83d96afcd6c585e936e214c1650c547b0f2',
            hash('sha256', $pk2->toString())
        );
        $this->assertSame(
            '5c6767bcff03fb9409e11137f91aab84c41a07b31dd3164555e96f5bde56e9df',
            hash('sha256', $pk2->toMultibase())
        );
    }
}
