<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Encoding\Base58BtcVarTime;
use FediE2EE\PKD\Crypto\Encoding\Multibase;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Property-based tests for round trip operations.
 *
 * These tests verify that encode/decode pairs are true inverses:
 * decode(encode(x)) == x for all valid inputs.
 */
#[CoversClass(Base58BtcVarTime::class)]
#[CoversClass(Multibase::class)]
#[CoversClass(Version1::class)]
#[CoversClass(PublicKey::class)]
#[CoversClass(SecretKey::class)]
class RoundTripTest extends TestCase
{
    use TestTrait;

    /**
     * Property: Base58 encode/decode is a roundtrip for arbitrary binary data.
     *
     * decode(encode(x)) == x
     */
    public function testBase58Roundtrip(): void
    {
        $this->forAll(
            Generators::string()
        )->then(function (string $input): void {
            $encoded = Base58BtcVarTime::encode($input);
            $decoded = Base58BtcVarTime::decode($encoded);
            $this->assertSame(
                $input,
                $decoded,
                'Base58 roundtrip failed for input of length ' . strlen($input)
            );
        });
    }

    /**
     * Property: Base58 encoding produces only valid Base58 characters.
     *
     * encode(x) ⊆ Base58Alphabet
     */
    public function testBase58OutputAlphabet(): void
    {
        $base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($base58Alphabet): void {
            $encoded = Base58BtcVarTime::encode($input);
            for ($i = 0; $i < strlen($encoded); $i++) {
                $this->assertStringContainsString(
                    $encoded[$i],
                    $base58Alphabet,
                    "Invalid Base58 character at position $i"
                );
            }
        });
    }

    /**
     * Property: Multibase encode/decode is a roundtrip for arbitrary binary data.
     *
     * decode(encode(x)) == x (for both base64url and base58)
     */
    public function testMultibaseRoundtrip(): void
    {
        $this->forAll(
            Generators::string(),
            Generators::bool()  // useUnsafe (base58) flag
        )->then(function (string $input, bool $useBase58): void {
            $encoded = Multibase::encode($input, $useBase58);
            $decoded = Multibase::decode($encoded);
            $this->assertSame(
                $input,
                $decoded,
                'Multibase roundtrip failed (base58=' . ($useBase58 ? 'true' : 'false') . ')'
            );
        });
    }

    /**
     * Property: Multibase encoding starts with correct prefix.
     *
     * encode(x, false) starts with 'u' (base64url)
     * encode(x, true) starts with 'z' (base58btc)
     */
    public function testMultibasePrefix(): void
    {
        $this->forAll(
            Generators::string()
        )->then(function (string $input): void {
            $base64Encoded = Multibase::encode($input, false);
            $base58Encoded = Multibase::encode($input, true);

            $this->assertStringStartsWith('u', $base64Encoded, 'Base64url should start with "u"');
            $this->assertStringStartsWith('z', $base58Encoded, 'Base58btc should start with "z"');
        });
    }

    /**
     * Property: Attribute encryption is a roundtrip.
     *
     * decrypt(encrypt(plaintext, key), key) == plaintext
     */
    public function testAttributeEncryptionRoundtrip(): void
    {
        $this->forAll(
            Generators::string(),  // plaintext
            Generators::string()   // attribute name
        )->then(function (string $plaintext, string $attributeName): void {
            $v1 = new Version1();
            $key = SymmetricKey::generate();
            $merkleRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

            $encrypted = $v1->encryptAttribute($attributeName, $plaintext, $key, $merkleRoot);
            $decrypted = $v1->decryptAttribute($attributeName, $encrypted, $key, $merkleRoot);

            $this->assertSame(
                $plaintext,
                $decrypted,
                'Attribute encryption roundtrip failed'
            );
        });
    }

    /**
     * Property: Ciphertext is different from plaintext (for non-empty input).
     *
     * encrypt(plaintext) != plaintext (when |plaintext| > 0)
     */
    public function testEncryptionProducesDifferentOutput(): void
    {
        $this->forAll(
            Generators::string()
        )
        ->when(fn(string $s) => strlen($s) > 0)  // Skip empty strings
        ->then(function (string $plaintext): void {
            $v1 = new Version1();
            $key = SymmetricKey::generate();
            $merkleRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

            $encrypted = $v1->encryptAttribute('test', $plaintext, $key, $merkleRoot);

            $this->assertNotSame(
                $plaintext,
                $encrypted,
                'Ciphertext should differ from plaintext'
            );
        });
    }

    /**
     * Property: PublicKey toString/fromString is a roundtrip.
     *
     * fromString(toString(pk)) == pk
     */
    public function testPublicKeyStringRoundtrip(): void
    {
        // Generate multiple random keys and test roundtrip
        $this->forAll(
            Generators::choose(1, 100)  // Just a counter to generate multiple keys
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $publicKey = $secretKey->getPublicKey();

            $stringForm = $publicKey->toString();
            $restored = PublicKey::fromString($stringForm);

            $this->assertSame(
                $publicKey->getBytes(),
                $restored->getBytes(),
                'PublicKey string roundtrip failed'
            );
            $this->assertSame(
                $publicKey->getAlgo(),
                $restored->getAlgo(),
                'PublicKey algorithm mismatch after roundtrip'
            );
        });
    }

    /**
     * Property: PublicKey PEM encode/import is a roundtrip.
     *
     * importPem(encodePem(pk)) == pk
     */
    public function testPublicKeyPemRoundtrip(): void
    {
        $this->forAll(
            Generators::choose(1, 100)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $publicKey = $secretKey->getPublicKey();

            $pem = $publicKey->encodePem();
            $restored = PublicKey::importPem($pem);

            $this->assertSame(
                $publicKey->getBytes(),
                $restored->getBytes(),
                'PublicKey PEM roundtrip failed'
            );
        });
    }

    /**
     * Property: SecretKey PEM encode/import is a roundtrip.
     *
     * importPem(encodePem(sk)) == sk
     */
    public function testSecretKeyPemRoundtrip(): void
    {
        $this->forAll(
            Generators::choose(1, 100)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();

            $pem = $secretKey->encodePem();
            $restored = SecretKey::importPem($pem);

            $this->assertSame(
                $secretKey->getBytes(),
                $restored->getBytes(),
                'SecretKey PEM roundtrip failed'
            );
        });
    }

    /**
     * Property: PublicKey Multibase encode/decode is a roundtrip.
     *
     * fromMultibase(toMultibase(pk)) == pk
     */
    public function testPublicKeyMultibaseRoundtrip(): void
    {
        $this->forAll(
            Generators::choose(1, 100),
            Generators::bool()  // useUnsafe flag
        )->then(function (int $_counter, bool $useUnsafe): void {
            $secretKey = SecretKey::generate();
            $publicKey = $secretKey->getPublicKey();

            $multibase = $publicKey->toMultibase($useUnsafe);
            $restored = PublicKey::fromMultibase($multibase);

            $this->assertSame(
                $publicKey->getBytes(),
                $restored->getBytes(),
                'PublicKey Multibase roundtrip failed (useUnsafe=' . ($useUnsafe ? 'true' : 'false') . ')'
            );
        });
    }

    /**
     * Property: Sign/verify is consistent.
     *
     * verify(sign(message, sk), pk) == true
     */
    public function testSignatureVerification(): void
    {
        $this->forAll(
            Generators::string()  // message to sign
        )->then(function (string $message): void {
            $secretKey = SecretKey::generate();
            $publicKey = $secretKey->getPublicKey();

            $signature = $secretKey->sign($message);
            $isValid = $publicKey->verify($signature, $message);

            $this->assertTrue($isValid, 'Signature verification failed');
        });
    }

    /**
     * Property: Signatures are deterministic.
     *
     * sign(m, sk) == sign(m, sk) for same message and key
     */
    public function testSignaturesDeterministic(): void
    {
        $this->forAll(
            Generators::string()
        )->then(function (string $message): void {
            $secretKey = SecretKey::generate();

            $sig1 = $secretKey->sign($message);
            $sig2 = $secretKey->sign($message);

            $this->assertSame($sig1, $sig2, 'Signatures should be deterministic');
        });
    }

    /**
     * Property: Wrong key fails verification.
     *
     * verify(sign(m, sk1), pk2) == false (when sk1 != sk2)
     */
    public function testWrongKeyFailsVerification(): void
    {
        $this->forAll(
            Generators::string()
        )->then(function (string $message): void {
            $secretKey1 = SecretKey::generate();
            $secretKey2 = SecretKey::generate();

            $signature = $secretKey1->sign($message);
            $isValid = $secretKey2->getPublicKey()->verify($signature, $message);

            $this->assertFalse($isValid, 'Verification with wrong key should fail');
        });
    }
}
