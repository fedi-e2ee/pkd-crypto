<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\Handler;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\Parser;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use Mdanter\Ecc\Exception\InsecureCurveException;
use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use PHPUnit\Framework\TestCase;
use SodiumException;

class HandlerTest extends TestCase
{
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
    }

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
     * @throws JsonException
     * @throws NotImplementedException
     * @throws InsecureCurveException
     * @throws HPKEException
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
}
