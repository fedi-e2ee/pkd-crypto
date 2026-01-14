<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    JsonException,
    NotImplementedException,
    ParserException
};
use FediE2EE\PKD\Crypto\Protocol\{
    Actions\AddKey,
    EncryptedActions\EncryptedAddKey,
    Handler,
    ParsedMessage,
    Parser
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use FediE2EE\PKD\Crypto\{
    Merkle\Tree,
    PublicKey,
    SecretKey,
    SymmetricKey
};
use ParagonIE\HPKE\{
    Factory,
    HPKEException,
    KEM\DHKEM\Curve,
    KEM\DHKEM\DecapsKey
};
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
            'fedie2ee@mastodon.social',
            $publicKey
        );
        $encryptedAddKey = $addKey->encrypt($keyMap);

        $handler = new Handler();
        $message = $handler->handle($encryptedAddKey, $secretKey, $keyMap, $recent);
        $wrapped = $handler->hpkeEncrypt($message, $encapsKey, $hpke);
        $this->assertIsString($wrapped);
        $this->assertMatchesRegularExpression('#^hpke:[0-9A-Za-z-_]+$#', $wrapped);

        $parser = new Parser();
        $decryptedMessage = $parser->decryptAndParse($wrapped, $decapsKey, $encapsKey, $hpke, $publicKey);
        $this->assertInstanceOf(ParsedMessage::class, $decryptedMessage);
        $this->assertInstanceOf(EncryptedAddKey::class, $decryptedMessage->getMessage());
        $this->assertInstanceOf(AttributeKeyMap::class, $decryptedMessage->getKeyMap());

        $decrypted = $decryptedMessage->getMessage()->decrypt($decryptedMessage->getKeyMap());
        $this->assertInstanceOf(AddKey::class, $decrypted);
    }


    public function testAdditionalParse(): void
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

        $parser = new Parser();
        $parsed = $parser->decryptAndParse($encrypted, $decapsKey, $encapsKey, $hpke, $publicKey);
        $this->assertInstanceOf(ParsedMessage::class, $parsed);
    }

    public static function invalidFromFuzzer(): array
    {
        return [
            [sodium_hex2bin('18181818182d2d302d2d2d2d2d2d7e50f3')],
            [sodium_hex2bin('402f2f2f2f2f2f2f2f2f2f2f2f2f30')],
        ];
    }

    #[DataProvider("invalidFromFuzzer")]
    public function testInvalidInput(string $input): void
    {
        $this->expectException(BundleException::class);
        Parser::fromJson($input);
    }

    #[DataProvider("invalidFromFuzzer")]
    public function testInvalidInputForActivityPub(string $input): void
    {
        $this->expectException(BundleException::class);
        (new Parser())->parseUnverifiedForActivityPub($input);
    }
}
