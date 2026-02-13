<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    InputException,
    JsonException,
    NotImplementedException,
    ParserException,
};
use FediE2EE\PKD\Crypto\Protocol\Actions\{
    AddKey,
    BurnDown
};
use GuzzleHttp\Exception\GuzzleException;
use FediE2EE\PKD\Crypto\Protocol\{
    Handler,
    Bundle,
    Parser
};
use FediE2EE\PKD\Crypto\{
    Merkle\Tree,
    SecretKey,
    SymmetricKey
};
use Mdanter\Ecc\Exception\InsecureCurveException;
use ParagonIE\HPKE\{
    Factory,
    HPKE
};
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\{
    Curve,
    DecapsKey
};
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

class HandlerTest extends TestCase
{
    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws ParserException
     * @throws SodiumException
     * @throws RandomException
     */
    public function testHandler(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('foo', new SymmetricKey(random_bytes(32)));

        $addKey = new AddKey(
            'fedie2ee@mastodon.social',
            $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);

        $bundler = new Handler();
        $message = $bundler->handle($encryptedAddKey, $secretKey, $keyMap, str_repeat("\x00", 32));
        $json = $message->toJson();
        $this->assertIsString($json);

        $parser = new Parser();
        $parsed = $parser->parse($json, $publicKey);
        $encrypted = $parsed->getMessage();
        $newKeyMap = $parsed->getKeyMap();

        $this->assertSame($addKey->getAction(), $encrypted->getAction());
        $this->assertEquals($keyMap, $newKeyMap);

        $parsed = $parser->parseUnverified($json);
        $encrypted = $parsed->getMessage();
        $newKeyMap = $parsed->getKeyMap();

        $this->assertSame($addKey->getAction(), $encrypted->getAction());
        $this->assertEquals($keyMap, $newKeyMap);
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
    public function testHpke(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('foo', new SymmetricKey(random_bytes(32)));

        $addKey = new AddKey(
            'fedie2ee@mastodon.social',
            $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);

        $bundler = new Handler();
        $message = $bundler->handle($encryptedAddKey, $secretKey, $keyMap, str_repeat("\x00", 32));

        $ciphersuite = Factory::init('DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM');
        $hpke = new HPKE($ciphersuite->kem, $ciphersuite->kdf, $ciphersuite->aead);
        [$skR, $pkR] = $hpke->kem->generateKeys();

        $encrypted = $bundler->hpkeEncrypt($message, $pkR, $hpke);

        $parser = new Parser();
        $decrypted = $parser->hpkeDecrypt($encrypted, $skR, $pkR, $hpke);
        $this->assertEquals($message, $decrypted);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testMessageFromJson(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('foo', new SymmetricKey(random_bytes(32)));

        $addKey = new AddKey(
            'fedie2ee@mastodon.social',
            $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);

        $bundler = new Handler();
        $message = $bundler->handle($encryptedAddKey, $secretKey, $keyMap, str_repeat("\x00", 32));
        $json = $message->toJson();
        $this->assertIsString($json);
        $newMessage = Bundle::fromJson($json);

        $this->assertEquals($message, $newMessage);
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testHandle(): void
    {
        // Generate a keypair
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();

        // Create an inaugural AddKey message
        $message = new AddKey(
            actor: "fedie2ee@mastodon.social",
            publicKey: $publicKey
        );

        // Map attributes to randomly-generated keys:
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        $merkleRoot = (new Tree([random_bytes(32)]))->getEncodedRoot();

        $handler = new Handler();
        $bundle = $handler->handle($message, $secretKey, $keyMap, $merkleRoot);

        $this->assertInstanceOf(Bundle::class, $bundle);
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws InsecureCurveException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testAdditionalHpkeEncrypt(): void
    {
        // Generate a keypair
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();

        // Create an inaugural AddKey message
        $message = new AddKey(
            actor: "fedie2ee@mastodon.social",
            publicKey: $publicKey
        );

        // Map attributes to randomly-generated keys:
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        $merkleRoot = (new Tree([random_bytes(32)]))->getEncodedRoot();

        $handler = new Handler();
        $bundle = $handler->handle($message, $secretKey, $keyMap, $merkleRoot);

        // HPKE encryption
        $hpke = Factory::init('DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305');
        $decapsKey = new DecapsKey(
            Curve::X25519,
            random_bytes(32)
        );
        $encapsKey = $decapsKey->getEncapsKey();

        $encrypted = $handler->hpkeEncrypt($bundle, $encapsKey, $hpke);
        $this->assertIsString($encrypted);
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testHandleBurnDownEncryptsAttributes(): void
    {
        $secretKey = SecretKey::generate();
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('operator', SymmetricKey::generate());

        $merkleRoot = (new Tree([random_bytes(32)]))->getEncodedRoot();
        $burnDown = new BurnDown(
            actor: 'https://example.com/users/foo',
            operator: 'https://pkd.example.org'
        );

        $handler = new Handler();
        $bundle = $handler->handle($burnDown, $secretKey, $keyMap, $merkleRoot);

        $this->assertInstanceOf(Bundle::class, $bundle);
        $this->assertSame('BurnDown', $bundle->getAction());

        $message = $bundle->getMessage();
        $this->assertArrayHasKey('actor', $message);
        $this->assertArrayHasKey('operator', $message);
        $this->assertArrayHasKey('time', $message);
        // actor and operator are attribute-encrypted
        $this->assertNotSame(
            'https://example.com/users/foo', $message['actor']
        );
        $this->assertNotSame(
            'https://pkd.example.org', $message['operator']
        );
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testHandleMessageNeedsEncryption(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        $merkleRoot = (new Tree([random_bytes(32)]))->getEncodedRoot();

        $addKey = new AddKey(
            actor: 'https://example.com/users/foo',
            publicKey: $publicKey
        );

        $handler = new Handler();
        $bundle = $handler->handle($addKey, $secretKey, $keyMap, $merkleRoot);

        $this->assertInstanceOf(Bundle::class, $bundle);
        $this->assertSame('AddKey', $bundle->getAction());

        $message = $bundle->getMessage();
        $this->assertArrayHasKey('actor', $message);
        $this->assertStringNotContainsString('https://', $message['actor']);
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testHandleAlreadyEncryptedMessage(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        $merkleRoot = (new Tree([random_bytes(32)]))->getEncodedRoot();
        $addKey = new AddKey(
            actor: 'https://example.com/users/foo',
            publicKey: $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);
        $originalMessage = $encryptedAddKey->toArray();

        $handler = new Handler();
        $bundle = $handler->handle($encryptedAddKey, $secretKey, $keyMap, $merkleRoot);

        $this->assertInstanceOf(Bundle::class, $bundle);
        $this->assertSame('AddKey', $bundle->getAction());

        $bundleMessage = $bundle->getMessage();
        $this->assertSame($originalMessage['actor'], $bundleMessage['actor'], 'double-encrypted test');
        $this->assertSame($originalMessage['public-key'], $bundleMessage['public-key'], 'double-encrypted test');
    }
}
