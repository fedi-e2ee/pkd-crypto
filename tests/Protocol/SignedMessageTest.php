<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(SignedMessage::class)]
class SignedMessageTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testSignVerify(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );
        $signature = $sm->sign($sk);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9-_]{86,88}$/', $signature);
        $decoded = Base64UrlSafe::decodeNoPadding($signature);
        $this->assertSame(64, mb_strlen($decoded, '8bit'));
        $this->assertTrue($sm->verify($pk));
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testWithEncryption(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $map = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        // Plaintext vs encrypted
        $plaintext = new AddKey('https://example.com/@alice', $pk);
        $encrypted = $plaintext->encrypt($map);

        $sm1 = SignedMessage::init($plaintext, $recent, $sk);
        $sm2 = SignedMessage::init($encrypted, $recent, $sk);
        $this->assertNotSame($sm1->jsonSerialize(), $sm2->jsonSerialize());
        $this->assertNotSame($sm1->getSignature(), $sm2->getSignature());
    }

    /**
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testToArrayContainsPkdContext(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = SignedMessage::init(
            new AddKey('https://example.com/@alice', $pk),
            $recent,
            $sk
        );

        $array = $sm->toArray();

        // Verify !pkd-context key exists and has correct value
        $this->assertArrayHasKey('!pkd-context', $array);
        $this->assertSame(SignedMessage::PKD_CONTEXT, $array['!pkd-context']);

        // Verify all required keys exist with correct association
        $this->assertArrayHasKey('action', $array);
        $this->assertSame('AddKey', $array['action']);

        $this->assertArrayHasKey('message', $array);
        $this->assertIsArray($array['message']);

        $this->assertArrayHasKey('recent-merkle-root', $array);
        $this->assertIsString($array['recent-merkle-root']);

        $this->assertArrayHasKey('signature', $array);
        $this->assertIsString($array['signature']);
    }

    /**
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testJsonSerializeMatchesToArray(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = SignedMessage::init(
            new AddKey('https://example.com/@alice', $pk),
            $recent,
            $sk
        );

        $this->assertSame($sm->toArray(), $sm->jsonSerialize());
    }

    /**
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testJsonOutputStructure(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = SignedMessage::init(
            new AddKey('https://example.com/@alice', $pk),
            $recent,
            $sk
        );

        $json = json_encode($sm);
        $this->assertIsString($json);

        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);

        // Verify JSON structure
        $this->assertArrayHasKey('!pkd-context', $decoded);
        $this->assertArrayHasKey('action', $decoded);
        $this->assertArrayHasKey('message', $decoded);
        $this->assertArrayHasKey('recent-merkle-root', $decoded);
        $this->assertArrayHasKey('signature', $decoded);

        // Verify key-value association is correct (not using > instead of =>)
        $this->assertSame(SignedMessage::PKD_CONTEXT, $decoded['!pkd-context']);
        $this->assertSame('AddKey', $decoded['action']);
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testGetSignatureThrowsWhenUnsigned(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Protocol Message is not signed');
        $sm->getSignature();
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyThrowsWhenUnsigned(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Protocol Message is not signed');
        $sm->verify($pk);
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyWithExplicitSignature(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );

        // Sign and get signature
        $signature = $sm->sign($sk);

        // Create new message and verify with explicit signature
        $sm2 = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );
        $this->assertTrue($sm2->verify($pk, $signature));
    }

    /**
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testGetInnerMessage(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $sm = new SignedMessage($addKey, $recent);

        $this->assertSame($addKey, $sm->getInnerMessage());
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testEncryptThrowsWhenAlreadyEncrypted(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $map = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $encrypted = $addKey->encrypt($map);
        $sm = new SignedMessage($encrypted, $recent);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('message is already encrypted');
        $sm->encrypt($map);
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testDecryptThrowsWhenNotEncrypted(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $map = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $sm = new SignedMessage($addKey, $recent);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('message is not encrypted');
        $sm->decrypt($map);
    }

    /**
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testEncodeForSigningContainsPkdContext(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );

        $encoded = $sm->encodeForSigning();
        $this->assertStringContainsString('!pkd-context', $encoded);
        $this->assertStringContainsString(SignedMessage::PKD_CONTEXT, $encoded);
    }

    /**
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testGetRecentMerkleRootIsPublic(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );

        $encodedRoot = $sm->getRecentMerkleRoot();
        $this->assertIsString($encodedRoot);
        $this->assertNotEmpty($encodedRoot);

        $this->assertGreaterThan(70, strlen($encodedRoot));
    }
}
