<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Revocation;
use FediE2EE\PKD\Crypto\SecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Tests for revocation token tampering resistance.
 *
 * Addresses missing tests for tokens with modified version prefix, modified REVOCATION_CONSTANT,
 * or public key being from a different keypair.
 */
#[CoversClass(Revocation::class)]
class RevocationTamperingTest extends TestCase
{
    /**
     * A token with a modified version prefix must be rejected.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsModifiedVersionPrefix(): void
    {
        $sk = SecretKey::generate();
        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);

        $decoded = Base64UrlSafe::decodeNoPadding($token);

        // Replace "FediPKD1" (first 8 bytes) with "FediPKD2"
        $tampered = 'FediPKD2' . substr($decoded, 8);
        $tamperedToken = Base64UrlSafe::encodeUnpadded($tampered);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid revocation header');
        $revocation->decode($tamperedToken);
    }

    /**
     * A token with a zeroed version prefix must be rejected.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsZeroedVersionPrefix(): void
    {
        $sk = SecretKey::generate();
        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);

        $decoded = Base64UrlSafe::decodeNoPadding($token);
        $tampered = str_repeat("\x00", 8) . substr($decoded, 8);
        $tamperedToken = Base64UrlSafe::encodeUnpadded($tampered);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid revocation header');
        $revocation->decode($tamperedToken);
    }

    /**
     * A token with a modified REVOCATION_CONSTANT must be rejected.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsModifiedRevocationConstant(): void
    {
        $sk = SecretKey::generate();
        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);

        $decoded = Base64UrlSafe::decodeNoPadding($token);

        // The REVOCATION_CONSTANT is bytes 8-57 (49 bytes)
        // Replace it with a different constant
        $tampered = substr($decoded, 0, 8)
            . str_repeat("\xFF", 49)
            . substr($decoded, 57);
        $tamperedToken = Base64UrlSafe::encodeUnpadded($tampered);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid revocation constant');
        $revocation->decode($tamperedToken);
    }

    /**
     * A token with partially modified REVOCATION_CONSTANT (single byte flip) must be rejected.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsSingleByteFlipInConstant(): void
    {
        $sk = SecretKey::generate();
        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);

        $decoded = Base64UrlSafe::decodeNoPadding($token);

        // Flip one byte in the REVOCATION_CONSTANT region
        $tampered = $decoded;
        $tampered[10] = chr(ord($decoded[10]) ^ 0x01);
        $tamperedToken = Base64UrlSafe::encodeUnpadded($tampered);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid revocation constant');
        $revocation->decode($tamperedToken);
    }

    /**
     * A token with the public key from a different keypair must fail signature verification.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsCrossKeyPublicKey(): void
    {
        $sk1 = SecretKey::generate();
        $sk2 = SecretKey::generate();
        $revocation = new Revocation();

        $token = $revocation->revokeThirdParty($sk1);

        // Verify with the wrong public key explicitly
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('mismatched public key');
        $revocation->verifyRevocationToken(
            $token,
            $sk2->getPublicKey()
        );
    }

    /**
     * A token with the public key bytes swapped to a different key (but keeping the original signature)
     * must fail verification.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsSwappedPublicKeyBytes(): void
    {
        $sk1 = SecretKey::generate();
        $sk2 = SecretKey::generate();
        $revocation = new Revocation();

        $token = $revocation->revokeThirdParty($sk1);
        $decoded = Base64UrlSafe::decodeNoPadding($token);

        // Replace the public key bytes (bytes 57-89) with sk2's
        $pk2Bytes = $sk2->getPublicKey()->getBytes();
        $tampered = substr($decoded, 0, 57)
            . $pk2Bytes
            . substr($decoded, 89);
        $tamperedToken = Base64UrlSafe::encodeUnpadded($tampered);

        // The embedded public key is now sk2's, but the signature was made by sk1 over sk1's data.
        // Verification should fail.
        $result = $revocation->verifyRevocationToken($tamperedToken);
        $this->assertFalse(
            $result,
            'Token with swapped public key bytes must fail'
        );
    }

    /**
     * A token with a modified signature must fail verification.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testRejectsModifiedSignature(): void
    {
        $sk = SecretKey::generate();
        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);

        $decoded = Base64UrlSafe::decodeNoPadding($token);

        // Flip a byte in the signature region (bytes 89+)
        $tampered = $decoded;
        $tampered[90] = chr(ord($decoded[90]) ^ 0xFF);
        $tamperedToken = Base64UrlSafe::encodeUnpadded($tampered);

        $result = $revocation->verifyRevocationToken($tamperedToken);
        $this->assertFalse(
            $result,
            'Token with modified signature must fail'
        );
    }

    /**
     * A truncated token must be rejected.
     *
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRejectsTruncatedToken(): void
    {
        $sk = SecretKey::generate();
        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);

        // Truncate to just the header + constant (no signature)
        $decoded = Base64UrlSafe::decodeNoPadding($token);
        $truncated = substr($decoded, 0, 60);
        $truncatedToken = Base64UrlSafe::encodeUnpadded($truncated);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Token is too short');
        $revocation->decode($truncatedToken);
    }
}
