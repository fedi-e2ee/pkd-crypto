<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use FediE2EE\PKD\Crypto\Exceptions\InvalidSignatureException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionException;
use SodiumException;

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

    /**
     * @throws CryptoException
     * @throws EncodingException
     */
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

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testEncodePem(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit PublicKeyTest.php')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));
        $encoded = $pk->encodePem();
        $expected = "-----BEGIN PUBLIC KEY-----\n" .
            'MCowBQYDK2VwAyEA/oXGYTQRev2uQ5jJvmubXo+moXZFmhKPcnHLFllM0K0=' . "\n" .
        "-----END PUBLIC KEY-----";
        $this->assertSame($expected, $encoded);
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

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testEncodePemLineLength(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test pem line length')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));
        $encoded = $pk->encodePem();

        // Extract the base64 content lines between header and footer
        $lines = explode("\n", $encoded);
        // Line 0 is "-----BEGIN PUBLIC KEY-----"
        // Line 1 is the base64 content
        // Line 2 is "-----END PUBLIC KEY-----"
        $this->assertCount(3, $lines);
        $this->assertSame('-----BEGIN PUBLIC KEY-----', $lines[0]);
        $base64Line = $lines[1];
        $this->assertSame('-----END PUBLIC KEY-----', $lines[2]);
        $this->assertLessThanOrEqual(64, strlen($base64Line));
        $this->assertNotEmpty($base64Line);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testToMultibaseDefaultUsesBase64(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test multibase default')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $default = $pk->toMultibase();
        $this->assertSame('u', $default[0], 'Default toMultibase should use base64url prefix "u"');
        $explicit = $pk->toMultibase(false);
        $this->assertSame('u', $explicit[0], 'toMultibase(false) should use base64url prefix "u"');
        $this->assertSame($default, $explicit);
        $unsafe = $pk->toMultibase(true);
        $this->assertSame('z', $unsafe[0], 'toMultibase(true) should use base58 prefix "z"');
        $this->assertNotSame($default, $unsafe);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testPemRoundTrip(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test pem round trip')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));
        $pem = $pk->encodePem();
        $imported = PublicKey::importPem($pem);
        $this->assertSame($pk->getBytes(), $imported->getBytes());
        $this->assertSame($pk->toString(), $imported->toString());
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testInvalidAlgVerify(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $signature = $sk->sign('test');
        $this->assertTrue($pk->verify($signature, 'test'));

        // Let's pretend it's RSA
        $rc = new ReflectionClass(PublicKey::class);
        $rc->getProperty('algo')->setValue($pk, 'rsa');
        $this->expectException(NotImplementedException::class);
        $pk->verify($signature, 'test');
    }

    public static function signatureProvider(): array
    {
        $sk = SecretKey::generate();
        $testCases = [
            [
                $sk,
                'message',
                $sk->sign('message'),
                true,
            ],
        ];

        return $testCases;
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    #[DataProvider("signatureProvider")]
    public function testVerify(
        SecretKey $secretKey,
        string $message,
        string $signature,
        bool $shouldBeValid,
    ): void {
        if (!$shouldBeValid) {
            $this->expectException(InvalidSignatureException::class);
            $secretKey->getPublicKey()->verifyThrow($signature, $message);
        }
        $this->assertSame(
            $shouldBeValid,
            $secretKey->getPublicKey()->verify($signature, $message)
        );
    }
}
