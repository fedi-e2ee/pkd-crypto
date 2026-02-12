<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\SymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(SymmetricKey::class)]
class SymmetricKeyTest extends TestCase
{
    public function testConstructorValidLength(): void
    {
        $key = new SymmetricKey(random_bytes(32));
        $this->assertSame(32, strlen($key->getBytes()));
    }

    public function testConstructorEmpty(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Symmetric key must be 32 bytes');
        new SymmetricKey('');
    }

    public function testConstructorTooShort(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Symmetric key must be 32 bytes');
        new SymmetricKey(random_bytes(16));
    }

    public function testConstructorTooLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Symmetric key must be 32 bytes');
        new SymmetricKey(random_bytes(64));
    }

    public function testGenerate(): void
    {
        $key = SymmetricKey::generate();
        $this->assertSame(32, strlen($key->getBytes()));

        $key2 = SymmetricKey::generate();
        $this->assertNotSame(
            $key->getBytes(),
            $key2->getBytes(),
            'Two generated keys should differ'
        );
    }

    /**
     * @throws SodiumException
     */
    public function testEncryptDecryptRoundtrip(): void
    {
        $key = SymmetricKey::generate();
        $plaintext = 'hello world';
        $ciphertext = $key->encrypt($plaintext);
        $decrypted = $key->decrypt($ciphertext);
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * @throws SodiumException
     */
    public function testEncryptDecryptWithAD(): void
    {
        $key = SymmetricKey::generate();
        $plaintext = 'hello world';
        $ad = 'associated data';
        $ciphertext = $key->encrypt($plaintext, $ad);
        $decrypted = $key->decrypt($ciphertext, $ad);
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * @throws SodiumException
     */
    public function testDecryptWrongKey(): void
    {
        $key1 = SymmetricKey::generate();
        $key2 = SymmetricKey::generate();
        $ciphertext = $key1->encrypt('secret');

        $this->expectException(SodiumException::class);
        $key2->decrypt($ciphertext);
    }

    /**
     * @throws SodiumException
     */
    public function testDecryptWrongAD(): void
    {
        $key = SymmetricKey::generate();
        $ciphertext = $key->encrypt('secret', 'correct-ad');

        $this->expectException(SodiumException::class);
        $key->decrypt($ciphertext, 'wrong-ad');
    }

    public function testNotJsonSerializable(): void
    {
        $key = SymmetricKey::generate();
        $json = json_encode($key);
        // Should not contain key material
        $this->assertStringNotContainsString(
            base64_encode($key->getBytes()),
            (string) $json,
            'json_encode must not leak key material'
        );
    }
}
