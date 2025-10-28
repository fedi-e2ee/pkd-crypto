<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    JsonException,
    NotImplementedException,
    ParserException
};
use FediE2EE\PKD\Crypto\Protocol\{Actions\AddKey, EncryptedActions\EncryptedAddKey, Handler, Parser, SignedMessage};
use ParagonIE\ConstantTime\Base64UrlSafe;
use FediE2EE\PKD\Crypto\{PublicKey, SecretKey, SymmetricKey};
use ParagonIE\HPKE\{
    Factory,
    HPKEException
};
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(Parser::class)]
class ParserTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws ParserException
     * @throws HPKEException
     * @throws SodiumException
     */
    public function testParser(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $hpke = Factory::dhkem_x25519sha256_hkdf_sha256_chacha20poly1305();
        [$decapsKey, $encapsKey] = $hpke->kem->generateKeys();

        $secretKey = SecretKey::generate();
        $publicKey = $secretKey->getPublicKey();
        $this->assertInstanceOf(PublicKey::class, $publicKey);

        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('foo', new SymmetricKey(random_bytes(32)));

        $addKey = new AddKey(
            'test-actor',
            $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);

        $handler = new Handler();
        $message = $handler->handle($encryptedAddKey, $secretKey, $keyMap, $recent);
        $wrapped = $handler->hpkeEncrypt($message, $encapsKey, $hpke);
        $this->assertIsString($wrapped);
        $this->assertMatchesRegularExpression('#^[0-9A-Za-z-_]+$#', $wrapped);

        $parser = new Parser();
        [$encrypted, $keyMap] = $parser->decryptAndParse($wrapped, $decapsKey, $hpke, $publicKey);
        $this->assertInstanceOf(EncryptedAddKey::class, $encrypted);
        $this->assertInstanceOf(AttributeKeyMap::class, $keyMap);

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(AddKey::class, $decrypted);
    }
}
