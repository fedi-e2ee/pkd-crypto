<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\AttributeEncryption;

use Exception;
use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Class CryptoShredTest
 * @package FediE2EE\PKDServer\Tests\Crypto\Compliance
 */
#[CoversClass(Version1::class)]
class Version1Test extends TestCase
{
    protected function getBasicData(): array
    {
        $v1 = new Version1();
        try {
            $ikm = SymmetricKey::generate();
            $merkle = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        } catch (Exception $ex) {
            $this->markTestIncomplete('PHP RNG failed');
        }
        return [$v1, $ikm, $merkle];
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testCryptoShred(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);
        $decrypted = $v1->decryptAttribute($attribute, $encrypted, $ikm, $merkle);
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testInvalidHMAC(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid authentication tag');
        $v1->decryptAttribute($attribute, $encrypted, new SymmetricKey(str_repeat("\xff", 32)), $merkle);
    }

    /**
     * @throws CryptoException
     * @throws Exception
     */
    public function testInvalidPlaintextCommitment(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid plaintext commitment');
        $v1->decryptAttribute($attribute, $encrypted, $ikm, random_bytes(32));
    }

    /**
     * @throws CryptoException
     */
    public function testInvalidVersion(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);
        $encrypted[0] = "\x00";

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid version');
        $v1->decryptAttribute($attribute, $encrypted, $ikm, $merkle);
    }

    public static function lenVectorProvider(): array
    {
        return [
            ['', '0000000000000000'],
            ['a', '0100000000000000'],
            ['hello', '0500000000000000'],
            [str_repeat('a', 256), '0001000000000000'],
            [str_repeat('x', 65535), 'ffff000000000000'],
        ];
    }

    #[DataProvider("lenVectorProvider")]
    public function testLenFunction(string $input, string $expectedHex): void
    {
        $this->assertSame($expectedHex, Hex::encode(Version1::len($input)));
    }

    /**
     * @throws SodiumException
     */
    public function testPlaintextCommitmentVectors(): void
    {
        $v1 = new Version1();
        $merkleRoot = "pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        $salt = str_repeat("\x01", 16);

        // Vector 1: Basic case
        $commit = $v1->getPlaintextCommitment("attr", "value", $merkleRoot, $salt);
        $this->assertSame(
            'e44a2495c3bba901706661d596e3f3cf1cabffc0be95fe91a3e529253d8c619c',
            Hex::encode($commit),
            'Plaintext commitment mismatch for basic case'
        );

        // Vector 2: Different attribute name
        $commit2 = $v1->getPlaintextCommitment("different-attr", "value", $merkleRoot, $salt);
        $this->assertSame(
            'd0ee4a5e3fdf590b4396286389db3de9120554174328e75eb44f9549d1bab75d',
            Hex::encode($commit2),
            'Plaintext commitment mismatch for different attribute'
        );

        // Vector 3: Different plaintext value
        $commit3 = $v1->getPlaintextCommitment("attr", "different-value", $merkleRoot, $salt);
        $this->assertSame(
            'ef1ece900516f45fa53af717f97760e5a0fdf5a9ff78084c70a7a5e99c6205b1',
            Hex::encode($commit3),
            'Plaintext commitment mismatch for different value'
        );
    }

    /**
     * @throws SodiumException
     */
    public function testPlaintextCommitmentOrderMatters(): void
    {
        $v1 = new Version1();
        $merkleRoot = "merkle-root";
        $salt = str_repeat("\x00", 16);

        // Swapping attribute and plaintext should produce different results
        $commit1 = $v1->getPlaintextCommitment("A", "B", $merkleRoot, $salt);
        $commit2 = $v1->getPlaintextCommitment("B", "A", $merkleRoot, $salt);
        $this->assertNotEquals(
            Hex::encode($commit1),
            Hex::encode($commit2),
            'Swapping attribute and plaintext should produce different commitments'
        );

        // Different merkle roots should also produce different results
        $commit3 = $v1->getPlaintextCommitment("attr", "val", "root1", $salt);
        $commit4 = $v1->getPlaintextCommitment("attr", "val", "root2", $salt);
        $this->assertNotEquals(
            Hex::encode($commit3),
            Hex::encode($commit4),
            'Different merkle roots should produce different commitments'
        );
    }

    public function testDecryptWrongAttributeName(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $encrypted = $v1->encryptAttribute('correct-attr', 'secret data', $ikm, $merkle);

        $this->expectException(CryptoException::class);
        $v1->decryptAttribute('wrong-attr', $encrypted, $ikm, $merkle);
    }

    public static function dataSizeProvider(): array
    {
        return [
            ['empty', ''],
            ['single byte', 'X'],
            ['short', 'hello'],
            ['medium', str_repeat('a', 1000)],
            ['with nulls', "data\x00with\x00nulls"],
        ];
    }

    #[DataProvider("dataSizeProvider")]
    public function testVariousDataSizes(string $label, string $plaintext): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $encrypted = $v1->encryptAttribute('test-attr', $plaintext, $ikm, $merkle);
        $decrypted = $v1->decryptAttribute('test-attr', $encrypted, $ikm, $merkle);
        $this->assertSame($plaintext, $decrypted, "Failed for: $label");
    }

    public function testTamperDetection(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $encrypted = $v1->encryptAttribute('attr', 'secret', $ikm, $merkle);

        // Tamper with random bytes (position 1-32)
        $tampered = $encrypted;
        $tampered[16] = chr(ord($tampered[16]) ^ 0xFF);
        try {
            $v1->decryptAttribute('attr', $tampered, $ikm, $merkle);
            $this->fail('Should have thrown for tampered random bytes');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('authentication', $e->getMessage());
        }

        // Tamper with commitment (position 33-64)
        $tampered2 = $encrypted;
        $tampered2[40] = chr(ord($tampered2[40]) ^ 0xFF);
        try {
            $v1->decryptAttribute('attr', $tampered2, $ikm, $merkle);
            $this->fail('Should have thrown for tampered commitment');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('authentication', $e->getMessage());
        }

        // Tamper with MAC (position 65-96)
        $tampered3 = $encrypted;
        $tampered3[70] = chr(ord($tampered3[70]) ^ 0xFF);
        try {
            $v1->decryptAttribute('attr', $tampered3, $ikm, $merkle);
            $this->fail('Should have thrown for tampered MAC');
        } catch (CryptoException $e) {
            $this->assertStringContainsString('authentication', $e->getMessage());
        }

        // Tamper with ciphertext (position 97+)
        if (strlen($encrypted) > 97) {
            $tampered4 = $encrypted;
            $tampered4[98] = chr(ord($tampered4[98]) ^ 0xFF);
            try {
                $v1->decryptAttribute('attr', $tampered4, $ikm, $merkle);
                $this->fail('Should have thrown for tampered ciphertext');
            } catch (CryptoException $e) {
                $this->assertStringContainsString('authentication', $e->getMessage());
            }
        }
    }
}
