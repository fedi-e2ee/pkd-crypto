<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    InputException,
    JsonException,
    NetworkException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\Protocol\{
    Actions\AddKey,
    Actions\RevokeKey,
    Bundle,
    EncryptedProtocolMessageInterface,
    Handler,
    HPKEAdapter,
    Parser,
    SignedMessage
};
use FediE2EE\PKD\Crypto\{
    SecretKey,
    SymmetricKey
};
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\HPKE\{
    Factory,
    HPKE,
    HPKEException
};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

/**
 * End-to-end round-trip test: Bundle -> Sign -> HPKE Encrypt
 * -> Decrypt -> Verify -> Parse -> Decrypt attributes.
 *
 * Addresses: Finding 3B - no round-trip test for full
 * protocol flow ensuring all components compose correctly.
 */
#[CoversClass(Handler::class)]
#[CoversClass(Parser::class)]
#[CoversClass(Bundle::class)]
#[CoversClass(SignedMessage::class)]
#[CoversClass(HPKEAdapter::class)]
class FullRoundTripTest extends TestCase
{
    public static function ciphersuites(): array
    {
        return [
            [Factory::dhkem_x25519sha256_hkdf_sha256_chacha20poly1305()],
            [Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm()],
        ];
    }

    /**
     * Full round-trip for AddKey:
     * 1. Create AddKey message
     * 2. Encrypt attributes with AttributeKeyMap
     * 3. Sign with SecretKey via Handler
     * 4. Encrypt bundle with HPKE
     * 5. Decrypt HPKE ciphertext
     * 6. Verify signature
     * 7. Decrypt attributes
     * 8. Assert original message contents match
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ciphersuites")]
    public function testAddKeyFullRoundTrip(HPKE $hpke): void
    {
        // 1. Setup keys
        $signingKey = SecretKey::generate();
        $verifyKey = $signingKey->getPublicKey();
        [$decapsKey, $encapsKey] = $hpke->kem->generateKeys();

        $sym1 = SymmetricKey::generate();
        $sym2 = SymmetricKey::generate();
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', $sym1)
            ->addKey('public-key', $sym2);

        $root = (new Tree([random_bytes(32)]))->getEncodedRoot();

        // 2. Create protocol message
        $addKey = new AddKey(
            'https://example.com/users/alice',
            $verifyKey
        );

        // 3. Sign via Handler (also encrypts attributes)
        $handler = new Handler();
        $bundle = $handler->handle($addKey, $signingKey, $keyMap, $root);
        $this->assertInstanceOf(Bundle::class, $bundle);
        $this->assertSame('AddKey', $bundle->getAction());

        // 4. Encrypt bundle with HPKE
        $hpkeCiphertext = $handler->hpkeEncrypt(
            $bundle,
            $encapsKey,
            $hpke
        );
        $this->assertIsString($hpkeCiphertext);
        $this->assertStringStartsWith('hpke:', $hpkeCiphertext);

        // 5. Decrypt HPKE ciphertext
        $parser = new Parser();
        $decryptedBundle = $parser->hpkeDecrypt(
            $hpkeCiphertext,
            $decapsKey,
            $encapsKey,
            $hpke
        );
        $this->assertInstanceOf(Bundle::class, $decryptedBundle);
        $this->assertSame('AddKey', $decryptedBundle->getAction());

        // 6. Verify signature
        $signedMsg = $decryptedBundle->toSignedMessage();
        $this->assertTrue(
            $signedMsg->verify($verifyKey),
            'Signature verification failed after HPKE round-trip'
        );

        // 7. Verify inner message is encrypted
        $inner = $signedMsg->getInnerMessage();
        $this->assertInstanceOf(
            EncryptedProtocolMessageInterface::class,
            $inner
        );

        // 8. Decrypt attributes and verify contents
        $decryptedKeyMap = $decryptedBundle->getSymmetricKeys();
        $this->assertTrue($decryptedKeyMap->hasKey('actor'));
        $this->assertTrue($decryptedKeyMap->hasKey('public-key'));

        $decryptedMsg = $signedMsg->decrypt($decryptedKeyMap);
        $this->assertInstanceOf(AddKey::class, $decryptedMsg);
        $this->assertSame(
            'https://example.com/users/alice',
            $decryptedMsg->getActor()
        );
        $this->assertSame(
            $verifyKey->toString(),
            $decryptedMsg->getPublicKey()->toString()
        );
    }

    /**
     * Full round-trip for RevokeKey.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ciphersuites")]
    public function testRevokeKeyFullRoundTrip(HPKE $hpke): void
    {
        $signingKey = SecretKey::generate();
        $revokedKey = SecretKey::generate()->getPublicKey();
        [$decapsKey, $encapsKey] = $hpke->kem->generateKeys();

        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $root = (new Tree([random_bytes(32)]))->getEncodedRoot();

        $revokeMsg = new RevokeKey(
            'https://example.com/users/bob',
            $revokedKey
        );

        $handler = new Handler();
        $bundle = $handler->handle(
            $revokeMsg,
            $signingKey,
            $keyMap,
            $root
        );

        $hpkeCiphertext = $handler->hpkeEncrypt(
            $bundle,
            $encapsKey,
            $hpke
        );

        $parser = new Parser();
        $decryptedBundle = $parser->hpkeDecrypt(
            $hpkeCiphertext,
            $decapsKey,
            $encapsKey,
            $hpke
        );

        $signedMsg = $decryptedBundle->toSignedMessage();
        $this->assertTrue(
            $signedMsg->verify($signingKey->getPublicKey())
        );

        $decryptedMsg = $signedMsg->decrypt(
            $decryptedBundle->getSymmetricKeys()
        );
        $this->assertInstanceOf(RevokeKey::class, $decryptedMsg);
        $this->assertSame(
            'https://example.com/users/bob',
            $decryptedMsg->getActor()
        );
        $this->assertSame(
            $revokedKey->toString(),
            $decryptedMsg->getPublicKey()->toString()
        );
    }

    /**
     * Verifies that JSON serialization round-trip preserves
     * all bundle contents including symmetric keys.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testBundleJsonRoundTrip(): void
    {
        $signingKey = SecretKey::generate();
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $root = (new Tree([random_bytes(32)]))->getEncodedRoot();

        $addKey = new AddKey(
            'https://example.com/users/carol',
            $signingKey->getPublicKey()
        );

        $handler = new Handler();
        $bundle = $handler->handle(
            $addKey,
            $signingKey,
            $keyMap,
            $root
        );

        // Serialize to JSON and back
        $json = $bundle->toJson();
        $restored = Bundle::fromJson($json);

        $this->assertSame(
            $bundle->getAction(),
            $restored->getAction()
        );
        $this->assertSame(
            $bundle->getRecentMerkleRoot(),
            $restored->getRecentMerkleRoot()
        );
        $this->assertSame(
            $bundle->getSignature(),
            $restored->getSignature()
        );
        $sm = $restored->toSignedMessage();
        $this->assertTrue(
            $sm->verify($signingKey->getPublicKey())
        );
    }

    /**
     * Verify that a wrong key fails signature verification
     * after a full round-trip.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ciphersuites")]
    public function testWrongKeyFailsAfterRoundTrip(
        HPKE $hpke
    ): void {
        $signingKey = SecretKey::generate();
        $wrongKey = SecretKey::generate();
        [$decapsKey, $encapsKey] = $hpke->kem->generateKeys();

        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $root = (new Tree([random_bytes(32)]))->getEncodedRoot();

        $addKey = new AddKey(
            'https://example.com/users/dave',
            $signingKey->getPublicKey()
        );

        $handler = new Handler();
        $bundle = $handler->handle(
            $addKey,
            $signingKey,
            $keyMap,
            $root
        );

        $encrypted = $handler->hpkeEncrypt(
            $bundle,
            $encapsKey,
            $hpke
        );

        $parser = new Parser();
        $decrypted = $parser->hpkeDecrypt(
            $encrypted,
            $decapsKey,
            $encapsKey,
            $hpke
        );

        $sm = $decrypted->toSignedMessage();
        $this->assertFalse(
            $sm->verify($wrongKey->getPublicKey()),
            'Wrong key should fail verification'
        );
    }
}
