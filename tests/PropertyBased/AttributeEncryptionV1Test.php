<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

class AttributeEncryptionV1Test extends TestCase
{
    use TestTrait;
    use ErisPhpUnit12Trait {
        ErisPhpUnit12Trait::getTestCaseAnnotations insteadof TestTrait;
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->erisSetupCompat();
    }

    public function testLengthInvariants(): void
    {
        $key = SymmetricKey::generate();
        $this->limitTo(10)->forAll(
            Generators::choose(1, 10000)
        )->then(function (int $length) use ($key): void {
            $root = 'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
            $v1 = new Version1();
            $plaintext = random_bytes($length);
            $ciphertext1 = $v1->encryptAttribute('example', $plaintext, $key, $root);
            $this->assertSame(
                $length + 97,
                strlen($ciphertext1),
                'ciphertext length incorrect'
            );
            $ciphertext2 = $v1->encryptAttribute('example', $plaintext, $key, $root);
            $this->assertSame(
                $length + 97,
                strlen($ciphertext1),
                'ciphertext length incorrect'
            );
            $this->assertNotSame($ciphertext1, $ciphertext2, 'randomized nonces should produce different ciphertexts');
        });
    }

    public function testKeyCommitment(): void
    {
        $v1 = new Version1();
        $key1 = SymmetricKey::generate();
        $key2 = SymmetricKey::generate();
        $root = 'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        $this->limitTo(10)->forAll(
            Generators::choose(1, 100)
        )->then(function (int $length) use ($v1, $key1, $key2, $root): void {
            $plaintext = random_bytes($length);
            $ciphertext = $v1->encryptAttribute('example', $plaintext, $key1, $root);
            try {
                $v1->decryptAttribute('example', $ciphertext, $key2, $root);
            } catch (CryptoException) {
                $this->assertNotSame($key1->getBytes(), $key2->getBytes());
                return;
            }
            $this->fail(
                "key commitment violated\n" .
                "key1 = " . sodium_bin2hex($key1->getBytes()) . "\n" .
                "key2 = " . sodium_bin2hex($key2->getBytes()) . "\n"
            );
        });
    }

    public function testAttributeNameCommitment(): void
    {
        $key = SymmetricKey::generate();
        $root = 'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        $this->limitTo(10)->forAll(
            Generators::choose(1, 100)
        )->then(function (int $length) use ($key, $root): void {
            $v1 = new Version1();
            $attribute = random_bytes($length);
            $wrong = 'wrong' . random_bytes($length);
            $ciphertext = $v1->encryptAttribute($attribute, 'example', $key, $root);
            try {
                $v1->decryptAttribute($wrong, $ciphertext, $key, $root);
                $this->fail("attribute name commitment violated");
            } catch (CryptoException) {
                $this->assertNotSame($attribute, $wrong);
            }
        });
    }

    public function testMerkleRootCommitment(): void
    {
        $key = SymmetricKey::generate();
        $this->limitTo(10)->forAll(
            Generators::choose(1, 100)
        )->then(function (int $length) use ($key): void {
            $v1 = new Version1();
            $root = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes($length));
            $wrong = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes($length));
            $ciphertext = $v1->encryptAttribute('test', 'example', $key, $root);
            try {
                $v1->decryptAttribute('test', $ciphertext, $key, $wrong);
                $this->fail("merkle root commitment violated");
            } catch (CryptoException) {
                $this->assertNotSame($root, $wrong);
            }
        });
    }
}
