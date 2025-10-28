<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\Handler;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\Parser;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKE;
use PHPUnit\Framework\TestCase;

class HandlerTest extends TestCase
{
    public function testHandler(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('foo', new SymmetricKey(random_bytes(32)));

        $addKey = new AddKey(
            'test-actor',
            $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);

        $bundler = new Handler();
        $message = $bundler->handle($encryptedAddKey, $secretKey, $keyMap, str_repeat("\x00", 32));
        $json = $message->toJson();
        $this->assertIsString($json);

        $parser = new Parser();
        [$encrypted, $newKeyMap] = $parser->parse($json, $publicKey);

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
            'test-actor',
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
        $decrypted = $parser->hpkeDecrypt($encrypted, $skR, $hpke);
        $this->assertEquals($message, $decrypted);
    }

    public function testMessageFromJson(): void
    {
        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('foo', new SymmetricKey(random_bytes(32)));

        $addKey = new AddKey(
            'test-actor',
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
}
