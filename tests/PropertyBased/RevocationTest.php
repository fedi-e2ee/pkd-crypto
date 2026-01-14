<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Revocation;
use FediE2EE\PKD\Crypto\SecretKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Property-based tests for revocation token handling.
 */
#[CoversClass(Revocation::class)]
class RevocationTest extends TestCase
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

    /**
     * Property: Revocation token created from key verifies with same key.
     *
     * verify(revokeThirdParty(sk), pk) == true
     */
    public function testRevocationTokenVerifies(): void
    {
        $this->forAll(
            Generators::choose(1, 100)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $publicKey = $secretKey->getPublicKey();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            $isValid = $revocation->verifyRevocationToken($token, $publicKey);
            $this->assertTrue($isValid, 'Revocation token should verify with correct key');
        });
    }

    /**
     * Property: Revocation token verifies without explicit public key.
     *
     * The token contains the public key, so verification should work.
     */
    public function testRevocationTokenVerifiesWithoutExplicitKey(): void
    {
        $this->forAll(
            Generators::choose(1, 100)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            // Verify without providing public key (uses embedded key)
            $isValid = $revocation->verifyRevocationToken($token);
            $this->assertTrue($isValid);
        });
    }

    /**
     * Property: Revocation token fails verification with wrong key.
     *
     * verify(revokeThirdParty(sk1), pk2) throws exception
     */
    public function testRevocationTokenFailsWithWrongKey(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey1 = SecretKey::generate();
            $secretKey2 = SecretKey::generate();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey1);

            $this->expectException(CryptoException::class);
            $this->expectExceptionMessage('mismatched public key');
            $revocation->verifyRevocationToken($token, $secretKey2->getPublicKey());
        });
    }

    /**
     * Property: Token decode extracts correct public key.
     */
    public function testTokenDecodeExtractsPublicKey(): void
    {
        $this->forAll(
            Generators::choose(1, 100)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $expectedPublicKey = $secretKey->getPublicKey();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            [$extractedPk, $signedData, $signature] = $revocation->decode($token);

            $this->assertSame(
                $expectedPublicKey->getBytes(),
                $extractedPk->getBytes(),
                'Decoded public key should match original'
            );
        });
    }

    /**
     * Property: Token is deterministic for same key.
     *
     * revokeThirdParty(sk) == revokeThirdParty(sk)
     */
    public function testTokenDeterministic(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();

            $revocation = new Revocation();
            $token1 = $revocation->revokeThirdParty($secretKey);
            $token2 = $revocation->revokeThirdParty($secretKey);

            $this->assertSame($token1, $token2, 'Revocation tokens should be deterministic');
        });
    }

    /**
     * Property: Different keys produce different tokens.
     */
    public function testDifferentKeysDifferentTokens(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey1 = SecretKey::generate();
            $secretKey2 = SecretKey::generate();

            $revocation = new Revocation();
            $token1 = $revocation->revokeThirdParty($secretKey1);
            $token2 = $revocation->revokeThirdParty($secretKey2);

            $this->assertNotSame($token1, $token2);
        });
    }

    /**
     * Property: Decode rejects truncated tokens.
     */
    public function testDecodeRejectsTruncatedTokens(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            // Truncate the token
            $truncated = substr($token, 0, (int)(strlen($token) * 0.5));

            try {
                $revocation->decode($truncated);
                $this->fail('Truncated token should be rejected');
            } catch (CryptoException $e) {
                $this->assertStringContainsString('too short', $e->getMessage());
            } catch (\Throwable $e) {
                // Base64 decode may throw on invalid input
                $this->assertTrue(true);
            }
        });
    }

    /**
     * Property: Decode rejects tokens with invalid header.
     */
    public function testDecodeRejectsInvalidHeader(): void
    {
        $this->forAll(
            Generators::choose(1, 20)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            // Corrupt the header (first few chars after base64 decode)
            $decoded = \ParagonIE\ConstantTime\Base64UrlSafe::decodeNoPadding($token);
            $corrupted = 'XXXXXXXX' . substr($decoded, 8);
            $corruptedToken = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($corrupted);

            $this->expectException(CryptoException::class);
            $revocation->decode($corruptedToken);
        });
    }

    /**
     * Property: Token length is consistent.
     *
     * All tokens should have the same length (deterministic structure).
     */
    public function testTokenLengthConsistent(): void
    {
        $lengths = [];

        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter) use (&$lengths): void {
            $secretKey = SecretKey::generate();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            $lengths[] = strlen($token);
        });

        // After all iterations, verify all lengths are the same
        $uniqueLengths = array_unique($lengths);
        $this->assertCount(1, $uniqueLengths, 'All revocation tokens should have same length');
    }

    /**
     * Property: Signature in token is valid Ed25519 signature.
     */
    public function testTokenContainsValidSignature(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();

            $revocation = new Revocation();
            $token = $revocation->revokeThirdParty($secretKey);

            [$pk, $signedData, $signature] = $revocation->decode($token);

            // Verify signature manually
            $isValid = $pk->verify($signature, $signedData);
            $this->assertTrue($isValid, 'Extracted signature should be valid');
        });
    }
}
