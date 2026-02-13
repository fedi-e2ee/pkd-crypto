<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\{
    AttributeEncryption\AttributeKeyMap,
    Merkle\Tree,
    SecretKey,
    SymmetricKey
};
use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    JsonException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\Protocol\{
    Actions\AddKey,
    EncryptedProtocolMessageInterface,
    Handler,
    HPKEAdapter,
    Parser
};
use ParagonIE\HPKE\{
    Factory,
    HPKE,
    HPKEException,
    Interfaces\DecapsKeyInterface,
    Interfaces\EncapsKeyInterface,
    KEM\DHKEM\DecapsKey
};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use GuzzleHttp\Exception\GuzzleException;
use Mdanter\Ecc\Exception\InsecureCurveException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(Handler::class)]
#[CoversClass(Parser::class)]
class HPKETest extends TestCase
{
    public static function ciphersuites(): array
    {
        return [
            [Factory::dhkem_x25519sha256_hkdf_sha256_chacha20poly1305()],
            [Factory::dhkem_x25519sha256_hkdf_sha256_aes128gcm()],
        ];
    }

    /**
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws SodiumException
     */
    #[DataProvider("ciphersuites")]
    public function testKeyID(HPKE $ciphersuite): void
    {
        $sk = new DecapsKey($ciphersuite->kem->curve, hash('sha256', 'test', true));
        $pk = $sk->getEncapsKey();
        $adapter = new HPKEAdapter($ciphersuite);
        $this->assertSame(
            '0eUvFqsTCHdJi7EGyqA5kB1cMXHX97Lui2uYOGN-R9A',
            Base64UrlSafe::encodeUnpadded($adapter->keyId($pk))
        );
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ciphersuites")]
    public function testRoundTrip(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->assertInstanceOf(DecapsKeyInterface::class, $decapsKey);
        $this->assertInstanceOf(EncapsKeyInterface::class, $encapsKey);

        $root = (new Tree([random_bytes(32)]))->getEncodedRoot();
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sym1 = SymmetricKey::generate();
        $sym2 = SymmetricKey::generate();

        // Create a dummy protocol message:
        $dummy = new AddKey('https://example.com/users/foo', $pk);
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', $sym1)
            ->addKey('public-key', $sym2);

        // HPKE encryption!
        $handler = new Handler();
        $bundle = $handler->handle($dummy->encrypt($keyMap), $sk, $keyMap, $root);
        $encrypted = $handler->hpkeEncrypt($bundle, $encapsKey, $ciphersuite);
        $this->assertIsString($encrypted);
        $this->assertTrue((new HPKEAdapter($ciphersuite))->isHpkeCiphertext($encrypted));

        // HPKE decryption!
        $parser = new Parser();
        $decrypted = $parser->hpkeDecrypt($encrypted, $decapsKey, $encapsKey, $ciphersuite);
        $this->assertSame($bundle->getAction(), $decrypted->getAction());
        $this->assertSame($bundle->toString(), $decrypted->toString());

        // Let's verify
        $sm1 = $bundle->toSignedMessage();
        $sm2 = $decrypted->toSignedMessage();
        $this->assertSame($sm1->toArray(), $sm2->toArray());
        $this->assertSame($sm1->toString(), $sm2->toString());
        $this->assertTrue($sm1->verify($pk));
        $this->assertTrue($sm2->verify($pk));

        // Let's extract the contents
        $m1 = $sm1->getInnerMessage();
        $m2 = $sm2->getInnerMessage();
        $this->assertInstanceOf(EncryptedProtocolMessageInterface::class, $m1);
        $this->assertInstanceOf(EncryptedProtocolMessageInterface::class, $m2);

        $map1 = $bundle->getSymmetricKeys();
        $map2 = $decrypted->getSymmetricKeys();
        $this->assertTrue($map1->hasKey('actor'));
        $this->assertTrue($map1->hasKey('public-key'));
        $this->assertTrue($map2->hasKey('actor'));
        $this->assertTrue($map2->hasKey('public-key'));

        $dec1 = $sm1->decrypt($map1);
        $dec2 = $sm2->decrypt($map2);
        $this->assertInstanceOf(AddKey::class, $dec1);
        $this->assertInstanceOf(AddKey::class, $dec2);
        $this->assertSame($dec1->toString(), $dec2->toString());
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ciphersuites")]
    public function testInvalidHPKEPayload(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->assertInstanceOf(EncapsKeyInterface::class, $encapsKey);

        $root = (new Tree([random_bytes(32)]))->getEncodedRoot();
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $dummy = new AddKey('https://example.com/users/foo', $pk);
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $handler = new Handler();
        $bundle = $handler->handle($dummy->encrypt($keyMap), $sk, $keyMap, $root);
        $encrypted = $handler->hpkeEncrypt($bundle, $encapsKey, $ciphersuite);
        $this->assertIsString($encrypted);
        $this->assertTrue((new HPKEAdapter($ciphersuite))->isHpkeCiphertext($encrypted));

        // OK, now let's mutate the sucker.
        $encrypted = 'hpke::' . substr($encrypted, 5);

        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey, $encrypted);
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testShortPayload(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('Invalid payload: too short');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'abcd');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testNotAsShortPayload(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('Invalid payload header');
        // Still wrong but different size
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'abcde');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testOnlyHeader(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'hpke:');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testInvalidPayloadExtra(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'hpke:abcd:efg');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testInvalidPayloadDoubleColon(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'hpke::abcdefg');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testInvalidPayloadTotallyInvalid(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'hpke:$!@^');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testInvalidPayloadSuffix(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey,'hpke:abcdefg:');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testOpenWithExactlyPrefixLength(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey, 'hpke:');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testOpenWithInvalidStartCharacter(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey, 'hpke:!abcdef');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testOpenWithInvalidEndCharacter(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey, 'hpke:abcdef!');
    }

    #[DataProvider("ciphersuites")]
    public function testIsHpkeCiphertextBoundary(HPKE $ciphersuite): void
    {
        $adapter = new HPKEAdapter($ciphersuite);
        $this->assertFalse($adapter->isHpkeCiphertext('hpke:'));
        $this->assertTrue($adapter->isHpkeCiphertext('hpke:A'));
        $this->assertFalse($adapter->isHpkeCiphertext('hpke:!A'));
        $this->assertFalse($adapter->isHpkeCiphertext('hpke:A!'));
        $this->assertTrue($adapter->isHpkeCiphertext('hpke:ABC123-_'));
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testExactly5BytesPassesLengthCheck(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('Invalid payload header');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey, 'test5');
    }

    /**
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testHpkePrefixOnlyPassesLengthCheck(HPKE $ciphersuite): void
    {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $this->expectException(HPKEException::class);
        $this->expectExceptionMessage('HPKE ciphertext must be base64url encoded without padding');
        (new HPKEAdapter($ciphersuite))->open($decapsKey, $encapsKey, 'hpke:');
    }
}
