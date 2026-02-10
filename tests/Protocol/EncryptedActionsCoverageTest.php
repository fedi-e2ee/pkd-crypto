<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NetworkException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\Actions\RevokeKey;
use FediE2EE\PKD\Crypto\Protocol\Actions\Fireproof;
use FediE2EE\PKD\Crypto\Protocol\Actions\UndoFireproof;
use FediE2EE\PKD\Crypto\Protocol\Actions\MoveIdentity;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedAddKey;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedRevokeKey;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedFireproof;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedUndoFireproof;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedMoveIdentity;
use FediE2EE\PKD\Crypto\Protocol\EncryptedProtocolMessageInterface;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(EncryptedAddKey::class)]
#[CoversClass(EncryptedRevokeKey::class)]
#[CoversClass(EncryptedFireproof::class)]
#[CoversClass(EncryptedUndoFireproof::class)]
#[CoversClass(EncryptedMoveIdentity::class)]
class EncryptedActionsCoverageTest extends TestCase
{
    /**
     * Encrypted AddKey should produce same-size ciphertext per field when inputs have the same length.
     *
     * Since XChaCha20-Poly1305 has 24-byte nonce + 16-byte tag overhead, ciphertext size = 40 + plaintext_length.
     * Actor names of the same length must produce the same ciphertext size.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testAddKeyCiphertextSizeConsistency(): void
    {
        $pk = SecretKey::generate()->getPublicKey();
        $sym = SymmetricKey::generate();
        $keyMap = (new AttributeKeyMap())->addKey('actor', $sym);

        // Two actors of identical string length
        $actor1 = 'https://example.com/users/alice';
        $actor2 = 'https://example.com/users/bobby';
        $this->assertSame(strlen($actor1), strlen($actor2));

        $msg1 = new AddKey($actor1, $pk);
        $msg2 = new AddKey($actor2, $pk);

        $enc1 = $msg1->encrypt($keyMap);
        $enc2 = $msg2->encrypt($keyMap);

        $arr1 = $enc1->toArray();
        $arr2 = $enc2->toArray();

        // Encrypted actor fields should be the same length
        $this->assertSame(
            strlen($arr1['actor']),
            strlen($arr2['actor']),
            'Same-length actors should produce same-size ciphertexts'
        );

        // But the ciphertexts should differ (random nonces)
        $this->assertNotSame(
            $arr1['actor'],
            $arr2['actor'],
            'Different plaintexts should produce different ciphertexts'
        );
    }

    /**
     * Re-encrypting the same message twice produces different
     * ciphertexts due to random nonces.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testEncryptionNonceRandomness(): void
    {
        $pk = SecretKey::generate()->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $msg = new AddKey(
            'https://example.com/users/alice',
            $pk
        );

        $enc1 = $msg->encrypt($keyMap);
        $enc2 = $msg->encrypt($keyMap);

        $arr1 = $enc1->toArray();
        $arr2 = $enc2->toArray();

        // Same sizes
        $this->assertSame(
            strlen($arr1['actor']),
            strlen($arr2['actor'])
        );

        // Different ciphertexts
        $this->assertNotSame(
            $arr1['actor'],
            $arr2['actor'],
            'Re-encryption must produce different ciphertext'
        );
    }

    /**
     * Encrypt-then-decrypt round-trip preserves all fields for AddKey.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testAddKeyEncryptDecryptRoundTrip(): void
    {
        $pk = SecretKey::generate()->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $original = new AddKey(
            'https://example.com/users/alice',
            $pk
        );

        $encrypted = $original->encrypt($keyMap);
        $this->assertInstanceOf(
            EncryptedProtocolMessageInterface::class,
            $encrypted
        );
        $this->assertSame('AddKey', $encrypted->getAction());

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(AddKey::class, $decrypted);
        $this->assertSame(
            $original->getActor(),
            $decrypted->getActor()
        );
        $this->assertSame(
            $original->getPublicKey()->toString(),
            $decrypted->getPublicKey()->toString()
        );
    }

    /**
     * Encrypt-then-decrypt round-trip preserves all fields for RevokeKey.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testRevokeKeyEncryptDecryptRoundTrip(): void
    {
        $pk = SecretKey::generate()->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $original = new RevokeKey(
            'https://example.com/users/bob',
            $pk
        );

        $encrypted = $original->encrypt($keyMap);
        $this->assertInstanceOf(
            EncryptedProtocolMessageInterface::class,
            $encrypted
        );
        $this->assertSame('RevokeKey', $encrypted->getAction());

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(RevokeKey::class, $decrypted);
        $this->assertSame(
            $original->getActor(),
            $decrypted->getActor()
        );
        $this->assertSame(
            $original->getPublicKey()->toString(),
            $decrypted->getPublicKey()->toString()
        );
    }

    /**
     * Encrypt-then-decrypt round-trip for Fireproof.
     *
     * @throws RandomException
     * @throws SodiumException
     */
    public function testFireproofEncryptDecryptRoundTrip(): void
    {
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor');

        $original = new Fireproof(
            'https://example.com/users/carol'
        );

        $encrypted = $original->encrypt($keyMap);
        $this->assertSame('Fireproof', $encrypted->getAction());

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(Fireproof::class, $decrypted);
        $this->assertSame(
            $original->getActor(),
            $decrypted->getActor()
        );
    }

    /**
     * Encrypt-then-decrypt round-trip for UndoFireproof.
     *
     * @throws RandomException
     * @throws SodiumException
     */
    public function testUndoFireproofEncryptDecryptRoundTrip(): void
    {
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor');

        $original = new UndoFireproof(
            'https://example.com/users/dave'
        );

        $encrypted = $original->encrypt($keyMap);
        $this->assertSame('UndoFireproof', $encrypted->getAction());

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(UndoFireproof::class, $decrypted);
        $this->assertSame(
            $original->getActor(),
            $decrypted->getActor()
        );
    }

    /**
     * Encrypt-then-decrypt round-trip for MoveIdentity.
     *
     * @throws RandomException
     * @throws SodiumException
     */
    public function testMoveIdentityEncryptDecryptRoundTrip(): void
    {
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('old-actor')
            ->addRandomKey('new-actor');

        $original = new MoveIdentity(
            'https://old.example.com/users/eve',
            'https://new.example.com/users/eve'
        );

        $encrypted = $original->encrypt($keyMap);
        $this->assertSame('MoveIdentity', $encrypted->getAction());

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(MoveIdentity::class, $decrypted);
    }

    /**
     * Signature verification works with encrypted messages.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testSignatureOverEncryptedMessage(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        $addKey = new AddKey(
            'https://example.com/users/alice',
            $pk
        );
        $encrypted = $addKey->encrypt($keyMap);

        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(
            random_bytes(32)
        );
        $sm = new SignedMessage($encrypted, $recent);
        $sm->sign($sk);

        // Verify with correct key
        $this->assertTrue($sm->verify($pk));

        // Verify with wrong key fails
        $wrongKey = SecretKey::generate()->getPublicKey();
        $this->assertFalse($sm->verify($wrongKey));
    }

    /**
     * Fields without keys in the AttributeKeyMap remain
     * in plaintext.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testPartialEncryption(): void
    {
        $pk = SecretKey::generate()->getPublicKey();

        // Only encrypt 'actor', leave 'public-key' and 'time' in plaintext
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor');

        $addKey = new AddKey(
            'https://example.com/users/alice',
            $pk
        );
        $encrypted = $addKey->encrypt($keyMap);
        $arr = $encrypted->toArray();

        // 'public-key' should be the same as original plaintext
        $this->assertSame(
            $pk->toString(),
            $arr['public-key']
        );

        // 'actor' should be encrypted (different from plaintext)
        $this->assertNotSame(
            'https://example.com/users/alice',
            $arr['actor']
        );
    }
}
