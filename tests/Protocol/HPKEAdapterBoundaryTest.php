<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\HPKE;
use FediE2EE\PKD\Crypto\Protocol\HPKEAdapter;
use ParagonIE\HPKE\HPKEException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for HPKEAdapter regex anchoring edge cases.
 */
#[CoversClass(HPKEAdapter::class)]
class HPKEAdapterBoundaryTest extends TestCase
{
    public static function ciphersuites(): array
    {
        return [
            [Factory::dhkem_x25519sha256_hkdf_sha256_chacha20poly1305()],
        ];
    }

    /**
     * Inputs with leading whitespace before valid base64url content must be rejected by isHpkeCiphertext.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsLeadingWhitespace(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke: ABC123"),
            'Leading space should be rejected'
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:\tABC123"),
            'Leading tab should be rejected'
        );
    }

    /**
     * Inputs with leading newline before valid base64url content must be rejected.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsLeadingNewline(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:\nABC123"),
            'Leading newline should be rejected'
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:\r\nABC123"),
            'Leading CRLF should be rejected'
        );
    }

    /**
     * Inputs with trailing newline after valid base64url content must be rejected.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsTrailingNewline(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:ABC123\n"),
            'Trailing newline should be rejected'
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:ABC123\r\n"),
            'Trailing CRLF should be rejected'
        );
    }

    /**
     * Inputs with trailing null byte after valid base64url content must be rejected.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsTrailingNullByte(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:ABC123\x00"),
            'Trailing null byte should be rejected'
        );
    }

    /**
     * Inputs with leading null byte before valid base64url content must be rejected.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsLeadingNullByte(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:\x00ABC123"),
            'Leading null byte should be rejected'
        );
    }

    /**
     * Inputs with leading special characters must be rejected.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsLeadingSpecialChars(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:!ABC123")
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:@ABC123")
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:=ABC123")
        );
    }

    /**
     * Inputs with trailing special characters must be rejected.
     */
    #[DataProvider("ciphersuites")]
    public function testRejectsTrailingSpecialChars(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:ABC123!")
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:ABC123=")
        );
        $this->assertFalse(
            $adapter->isHpkeCiphertext("hpke:ABC123 ")
        );
    }

    /**
     * Valid base64url inputs without padding must still be
     * accepted.
     */
    #[DataProvider("ciphersuites")]
    public function testAcceptsValidBase64url(
        HPKE $ciphersuite
    ): void {
        $adapter = new HPKEAdapter($ciphersuite);

        $this->assertTrue(
            $adapter->isHpkeCiphertext("hpke:ABC123")
        );
        $this->assertTrue(
            $adapter->isHpkeCiphertext("hpke:a0-_Zz")
        );
        $this->assertTrue(
            $adapter->isHpkeCiphertext(
                "hpke:abcdefghijklmnopqrstuvwxyz"
                . "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                . "0123456789-_"
            )
        );
    }

    /**
     * open() must also reject inputs with leading/trailing non-base64url characters after the hpke: prefix.
     *
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testOpenRejectsLeadingGarbage(
        HPKE $ciphersuite
    ): void {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $adapter = new HPKEAdapter($ciphersuite);

        $this->expectException(HPKEException::class);
        $adapter->open(
            $decapsKey,
            $encapsKey,
            "hpke:\nABCDEF1234"
        );
    }

    /**
     * open() must reject inputs with trailing garbage.
     *
     * @throws HPKEException
     */
    #[DataProvider("ciphersuites")]
    public function testOpenRejectsTrailingGarbage(
        HPKE $ciphersuite
    ): void {
        [$decapsKey, $encapsKey] = $ciphersuite->kem->generateKeys();
        $adapter = new HPKEAdapter($ciphersuite);

        $this->expectException(HPKEException::class);
        $adapter->open(
            $decapsKey,
            $encapsKey,
            "hpke:ABCDEF1234\n"
        );
    }
}
