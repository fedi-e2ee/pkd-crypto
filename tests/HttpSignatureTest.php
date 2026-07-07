<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    HttpSignatureException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    Enums\SigningAlgorithm,
    HttpSignature,
    PublicKey,
    SecretKey
};
use GuzzleHttp\Psr7\{
    Request,
    Response
};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use ParagonIE\ConstantTime\Base64;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(HttpSignature::class)]
class HttpSignatureTest extends TestCase
{
    use ExtraneousDataProviderTrait;

    /**
     * Deterministically derive a secret key from a static label
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    private static function skFromSeed(string $label, SigningAlgorithm $alg): SecretKey
    {
        $seed = sodium_crypto_generichash($label);
        return match ($alg) {
            SigningAlgorithm::ED25519 => new SecretKey(
                sodium_crypto_sign_secretkey(
                    sodium_crypto_sign_seed_keypair($seed)
                ),
                $alg
            ),
            SigningAlgorithm::MLDSA44 => new SecretKey($seed, $alg),
        };
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    private static function pkFromSeed(string $label, SigningAlgorithm $alg): PublicKey
    {
        return self::skFromSeed($label, $alg)->getPublicKey();
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("signingAlgorithmProvider")]
    public function testSignAndVerify(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('phpunit test case for fedi-e2ee/pkd-client', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], '{"hello": "world"}');

        $signedRequest = $httpSignature->sign($sk, $request, ['@method', '@path', 'host'], 'test-key-a');

        $this->assertTrue($signedRequest->hasHeader('Signature-Input'));
        $this->assertTrue($signedRequest->hasHeader('Signature'));

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringStartsWith('sig1=("@method" "@path" "host");', $signatureInput);
        $this->assertStringContainsString(';alg="' . $alg->value . '"', $signatureInput);
        $this->assertStringContainsString(';keyid="test-key-a"', $signatureInput);
        $this->assertMatchesRegularExpression('/;created=\d+/', $signatureInput);

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
        $this->assertTrue($httpSignature->verifyThrow($pk, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testMldsa44SignsWithCanonicalHttpAlgorithm(): void
    {
        $sk = self::skFromSeed('canonical mldsa http alg', SigningAlgorithm::MLDSA44);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        $signed = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key');
        $signatureInput = $signed->getHeaderLine('Signature-Input');

        $this->assertStringContainsString('alg="ml-dsa-44"', $signatureInput);
        $this->assertStringNotContainsString('alg="mldsa44"', $signatureInput);
        $this->assertTrue($httpSignature->verify($pk, $signed));
    }

    public static function invalidTimeoutsProvider(): array
    {
        return [
            [PHP_INT_MIN],
            [-1],
            [0],
            [1],
            [86401],
            [PHP_INT_MAX],
        ];
    }

    #[DataProvider("invalidTimeoutsProvider")]
    public function testInvalidTimeouts(int $timeoutWindow): void
    {
        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Invalid timeout window size: ' . $timeoutWindow);
        new HttpSignature('sig1', $timeoutWindow);
    }

    /**
     * Test valid boundary timeout values
     * @throws HttpSignatureException
     */
    public function testValidTimeoutBoundaries(): void
    {
        // Minimum valid timeout
        $sig1 = new HttpSignature('sig1', 2);
        $this->assertInstanceOf(HttpSignature::class, $sig1);

        // Maximum valid timeout
        $sig2 = new HttpSignature('sig2', 86400);
        $this->assertInstanceOf(HttpSignature::class, $sig2);

        // Mid-range value
        $sig3 = new HttpSignature('sig3', 300);
        $this->assertInstanceOf(HttpSignature::class, $sig3);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyMissingSignatureInput(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('test key', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // No Signature-Input header
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyMissingSignature(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('test key', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="' . $alg->value . '";created=1234567890'
            ],
            'body'
        );
        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('HTTP header missing: Signature');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowMissingHeaders(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('test key', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('HTTP header missing: Signature-Input');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignAndVerifyCustomLabel(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('custom label test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature('custom-sig');
        $request = new Request('GET', '/test', ['Host' => 'example.org']);

        $signedRequest = $httpSignature->sign($sk, $request, ['@method', '@path', 'host'], 'key-id');

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringStartsWith('custom-sig=', $signatureInput);

        $signature = $signedRequest->getHeaderLine('Signature');
        $this->assertStringStartsWith('custom-sig=:', $signature);

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyWrongKey(SigningAlgorithm $alg): void
    {
        $sk1 = self::skFromSeed('key 1', $alg);
        $pk2 = self::pkFromSeed('key 2', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        $signedRequest = $httpSignature->sign($sk1, $request, ['@method', 'host'], 'key-1');

        // Verify with wrong key should fail
        $this->assertFalse($httpSignature->verify($pk2, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyExpiredSignature(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('expired test', $alg);
        $pk = $sk->getPublicKey();

        // Use a small timeout window
        $httpSignature = new HttpSignature('sig1', 10);
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // Sign with a timestamp from the past (more than 10 seconds ago)
        $oldTime = time() - 100;
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $oldTime);

        // Verification should fail due to timeout
        $this->assertFalse($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * Test verification fails when 'created' parameter is not numeric.
     * This kills the LogicalOr mutation (|| to &&).
     *
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyNonNumericCreated(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('non-numeric created test', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="' . $alg->value . '";created=not-a-number',
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * Test verification at exactly the timeout boundary.
     * This kills the GreaterThan mutation (> to >=).
     *
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyExactTimeoutBoundary(SigningAlgorithm $alg): void
    {
        if (!extension_loaded('pqcrypto')) {
            $this->markTestSkipped('timeout tests are flakey');
        }
        $sk = self::skFromSeed('boundary test', $alg);
        $pk = $sk->getPublicKey();

        $timeout = 10;
        $httpSignature = new HttpSignature('sig1', $timeout);
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // Sign at exactly the timeout boundary (should pass with >)
        $exactBoundaryTime = time() - $timeout;
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $exactBoundaryTime);
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));

        // Sign just past the boundary (should fail)
        $pastBoundaryTime = time() - $timeout - 1;
        $signedRequest2 = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $pastBoundaryTime);
        $this->assertFalse($httpSignature->verify($pk, $signedRequest2));
    }

    /**
     * Test signing and verifying with regex special characters in label.
     * This kills the PregQuote mutation.
     *
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testLabelWithRegexSpecialCharacters(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('regex label test', $alg);
        $pk = $sk->getPublicKey();

        // Label with characters that need escaping in regex
        $httpSignature = new HttpSignature('sig.test+1');
        $request = new Request('GET', '/test', ['Host' => 'example.org']);
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key-id');

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * Test verification throws when Signature-Input cannot be parsed.
     *
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyInvalidSignatureInputFormat(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('invalid format test', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'invalid-format-no-equals',
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Invalid signature header');
        $httpSignature->verify($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testHeaderCaseNormalization(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('case normalization test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/path', [
            'Host' => 'example.com',
            'Content-Type' => 'application/json'
        ], 'body');

        // Sign with uppercase headers in the list
        $signedRequest = $httpSignature->sign(
            $sk,
            $request,
            ['@METHOD', '@PATH', 'HOST', 'CONTENT-TYPE'],
            'key'
        );

        // Verify the Signature-Input has lowercase headers
        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringContainsString('"@method"', $signatureInput);
        $this->assertStringContainsString('"@path"', $signatureInput);
        $this->assertStringContainsString('"host"', $signatureInput);
        $this->assertStringContainsString('"content-type"', $signatureInput);
        $this->assertStringNotContainsString('"@METHOD"', $signatureInput);
        $this->assertStringNotContainsString('"HOST"', $signatureInput);

        // Should still verify successfully
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifySignatureLabelNotFound(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('label not found test', $alg);

        // Create a signature using label "sig1" but verify with "sig2"
        $httpSignature = new HttpSignature('sig2');
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig2=("@method");alg="' . $alg->value . '";created=' . time(),
                'Signature' => 'sig1=:AAAA:', // Wrong label
            ],
            'body'
        );

        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowSignatureLabelNotFound(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('throw label test', $alg);

        $httpSignature = new HttpSignature('mysig');
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'mysig=("@method");alg="' . $alg->value . '";created=' . time(),
                'Signature' => 'othersig=:AAAA:',
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Signature extraction failed');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyUnsupportedAlgorithm(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('unsupported algo test', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="rsa-sha256";created=' . time(),
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowUnsupportedAlgorithm(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('unsupported algo throw', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="hmac-sha256";created=' . time(),
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Unsupported algorithm');
        $this->expectExceptionCode(0);
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowMissingAlgorithm(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('missing algo throw', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");created=' . time(),
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('No algorithm specified');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowMissingCreated(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('missing created throw', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="' . $alg->value . '"',
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Invalid or missing "created" parameter');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowExpiredSignature(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('expired throw test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature('sig1', 10);
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // Sign with old timestamp
        $oldTime = time() - 100;
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $oldTime);

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Timeout window exceeded');
        $httpSignature->verifyThrow($pk, $signedRequest);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowMissingSignatureHeader(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('missing sig header', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="' . $alg->value . '";created=' . time(),
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('HTTP header missing: Signature');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignWithMixedCaseHeaders(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('mixed case headers', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        // Request has headers with specific casing
        $request = new Request('GET', '/api/test', [
            'Host' => 'api.example.com',
            'Accept' => 'application/json',
            'X-Custom-Header' => 'custom-value'
        ]);

        // Sign with lowercase versions
        $signedRequest = $httpSignature->sign(
            $sk,
            $request,
            ['@method', '@path', 'host', 'accept', 'x-custom-header'],
            'key'
        );

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMethodIsLowercaseInSignatureBase(SigningAlgorithm $alg): void
    {
        $sk1 = self::skFromSeed('method case test 1', $alg);
        $sk2 = self::skFromSeed('method case test 2', $alg);
        $pk1 = $sk1->getPublicKey();

        $httpSignature = new HttpSignature();

        $request1 = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        $signed1 = $httpSignature->sign($sk1, $request1, ['@method'], 'key');
        $this->assertTrue($httpSignature->verify($pk1, $signed1));

        $request2 = new Request('get', '/foo', ['Host' => 'example.com'], 'body');
        $request3 = new Request('GET', '/foo', ['Host' => 'example.com'], 'body');

        $httpSignature2 = new HttpSignature();
        $created = time();
        $signed2 = $httpSignature2->sign($sk2, $request2, ['@method'], 'key', $created);
        $signed3 = $httpSignature2->sign($sk2, $request3, ['@method'], 'key', $created);

        if ($alg === SigningAlgorithm::ED25519) {
            // ML-DSA-44 signatures are not deterministic
            $this->assertSame(
                $signed2->getHeaderLine('Signature'),
                $signed3->getHeaderLine('Signature'),
                'Method case should be normalized'
            );
        }
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignWithSingleHeader(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('single header test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('GET', '/test', ['Host' => 'example.com']);

        $signedRequest = $httpSignature->sign($sk, $request, ['host'], 'key');

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringStartsWith('sig1=("host");', $signatureInput);

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignWithPathOnly(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('path only test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('GET', '/api/v1/resource', ['Host' => 'example.com']);

        $signedRequest = $httpSignature->sign($sk, $request, ['@path'], 'key');

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringContainsString('"@path"', $signatureInput);
        $this->assertStringNotContainsString('"@method"', $signatureInput);

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignatureExtractionExactLabel(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('exact label test', $alg);

        $httpSignature = new HttpSignature('sig1');
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="' . $alg->value . '";created=' . time(),
                'Signature' => 'sig10=:AAAA:, sig11=:BBBB:',
            ],
            'body'
        );
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMethodLowercasedInBase(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('method lowercase test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();

        // Sign with POST (uppercase in HTTP spec)
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');
        $signedRequest = $httpSignature->sign($sk, $request, ['@method'], 'key');

        // The signature should verify because method is normalized
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));

        // Verify the signature-input shows lowercase method in covered components
        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringContainsString('"@method"', $signatureInput);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testDefaultTimeoutIs300(SigningAlgorithm $alg): void
    {
        if (!extension_loaded('pqcrypto')) {
            $this->markTestSkipped('timeout tests are flakey');
        }
        $sk = self::skFromSeed('default timeout test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        // Let's ensure the signing time doesn't make it invalid
        $start = microtime(true);
        $httpSignature->sign($sk, $request, ['@method', 'host'], 'key');
        $diff = microtime(true) - round($start, 2);

        $created = (int) floor(microtime(true) - 299.0 - $diff);
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $created);
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));

        $created2 = time() - 301;
        $signedRequest2 = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $created2);
        $this->assertFalse($httpSignature->verify($pk, $signedRequest2));
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignatureParamsExtraction(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('params extraction test', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $created = time();
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'my-key-id', $created);

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');

        // Verify all params are present
        $this->assertStringContainsString('alg="' . $alg->value . '"', $signatureInput);
        $this->assertStringContainsString('keyid="my-key-id"', $signatureInput);
        $this->assertStringContainsString('created=' . $created, $signatureInput);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMissingSignatureInputWithSignaturePresent(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('missing sig input test', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature' => 'sig1=:' . str_repeat('A', 86) . ':',
            ],
            'body'
        );
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testUnknownHeadersAreSkipped(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('unknown headers test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/test',
            [
                'Host' => 'example.com',
                'X-Custom' => 'value',
            ],
            'body'
        );
        $signed = $httpSignature->sign($sk, $request, ['host', 'x-custom'], 'key');
        $this->assertTrue($httpSignature->verify($pk, $signed));
    }

    /**
     * Ed25519 signatures are deterministic, so POST and post
     * produce the same signature when signed with the same key.
     */
    public function testMethodLowercasedForConsistencyEd25519(): void
    {
        $sk = self::skFromSeed('method lowercase consistency', SigningAlgorithm::ED25519);

        $httpSignature = new HttpSignature();
        $created = time();

        $requestUpper = new Request('POST', '/test', ['Host' => 'example.com']);
        $requestLower = new Request('post', '/test', ['Host' => 'example.com']);

        $signedUpper = $httpSignature->sign($sk, $requestUpper, ['@method'], 'key', $created);
        $signedLower = $httpSignature->sign($sk, $requestLower, ['@method'], 'key', $created);
        $this->assertSame(
            $signedUpper->getHeaderLine('Signature'),
            $signedLower->getHeaderLine('Signature')
        );
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testPathInSignatureBase(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('path signature test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request1 = new Request('GET', '/path1', ['Host' => 'example.com']);
        $request2 = new Request('GET', '/path2', ['Host' => 'example.com']);

        $created = time();
        $signed1 = $httpSignature->sign($sk, $request1, ['@path'], 'key', $created);
        $signed2 = $httpSignature->sign($sk, $request2, ['@path'], 'key', $created);
        $this->assertTrue($httpSignature->verify($pk, $signed1));
        $this->assertTrue($httpSignature->verify($pk, $signed2));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testCustomTimeoutWindow(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('custom timeout window', $alg);
        $pk = $sk->getPublicKey();
        $httpSignature = new HttpSignature('sig1', 60);
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        $created = time() - 59;
        $signedRequest = $httpSignature->sign($sk, $request, ['@method'], 'key', $created);
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
        $created2 = time() - 61;
        $signedRequest2 = $httpSignature->sign($sk, $request, ['@method'], 'key', $created2);
        $this->assertFalse($httpSignature->verify($pk, $signedRequest2));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMissingRequiredHeaderFails(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('missing header test', $alg);

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method" "x-custom-missing");alg="' . $alg->value . '";created=' . time(),
                'Signature' => 'sig1=:' . str_repeat('A', 86) . ':',
            ],
            'body'
        );
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testForeachProcessesAllHeaders(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('foreach all headers', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/test/path',
            [
                'Host' => 'example.com',
                'Content-Type' => 'application/json',
                'X-Custom-1' => 'value1',
                'X-Custom-2' => 'value2',
            ],
            '{"test": true}'
        );

        $signed = $httpSignature->sign(
            $sk,
            $request,
            ['@method', '@path', 'host', 'content-type', 'x-custom-1', 'x-custom-2'],
            'key'
        );
        $this->assertTrue($httpSignature->verify($pk, $signed));
        $signatureInput = $signed->getHeaderLine('Signature-Input');

        $this->assertStringContainsString('"@method"', $signatureInput);
        $this->assertStringContainsString('"@path"', $signatureInput);
        $this->assertStringContainsString('"host"', $signatureInput);
        $this->assertStringContainsString('"content-type"', $signatureInput);
        $this->assertStringContainsString('"x-custom-1"', $signatureInput);
        $this->assertStringContainsString('"x-custom-2"', $signatureInput);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMethodDoesNotBreakLoop(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('method does not break loop', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/test/path',
            ['Host' => 'example.com'],
            'body'
        );
        $created = time();
        $signedWithAll = $httpSignature->sign(
            $sk,
            $request,
            ['@method', '@path', 'host'],
            'key',
            $created
        );
        $signedMethodOnly = $httpSignature->sign(
            $sk,
            $request,
            ['@method'],
            'key',
            $created
        );
        $this->assertTrue($httpSignature->verify($pk, $signedWithAll));
        $this->assertTrue($httpSignature->verify($pk, $signedMethodOnly));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testPathDoesNotBreakLoop(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('path does not break loop', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/test/path',
            ['Host' => 'example.com', 'X-Custom' => 'value'],
            'body'
        );

        $created = time();
        $signedWithAll = $httpSignature->sign(
            $sk,
            $request,
            ['@path', 'host', 'x-custom'],
            'key',
            $created
        );

        $signedPathOnly = $httpSignature->sign(
            $sk,
            $request,
            ['@path'],
            'key',
            $created
        );

        $this->assertTrue($httpSignature->verify($pk, $signedWithAll));
        $this->assertTrue($httpSignature->verify($pk, $signedPathOnly));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMissingCoveredHeaderRejectsVerify(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('missing header skipped', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();

        // Request has Host and X-Present but NOT X-Missing
        $request = new Request(
            'POST',
            '/test',
            ['Host' => 'example.com', 'X-Present' => 'value'],
            'body'
        );

        // Sign specifying x-missing (which doesn't exist in request)
        $signed = $httpSignature->sign(
            $sk,
            $request,
            ['host', 'x-present', 'x-missing'],
            'key'
        );

        // Verification must fail: x-missing is in covered components
        // but absent from the message
        $this->assertFalse($httpSignature->verify($pk, $signed));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowMissingCoveredHeader(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('missing header throw', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/test',
            ['Host' => 'example.com'],
            'body'
        );

        // Sign with x-absent listed in covered components
        $signed = $httpSignature->sign(
            $sk,
            $request,
            ['host', 'x-absent'],
            'key'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage(
            'Covered component header missing: x-absent'
        );
        $httpSignature->verifyThrow($pk, $signed);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyRejectsTamperedHeaderValue(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('tampered header test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/test',
            ['Host' => 'example.com', 'X-Present' => 'value'],
            'body'
        );

        $signed = $httpSignature->sign(
            $sk,
            $request,
            ['host', 'x-present'],
            'key'
        );

        // Tamper with X-Present header value
        $differentRequest = new Request(
            'POST',
            '/test',
            ['Host' => 'example.com', 'X-Present' => 'different-value'],
            'body'
        );
        $signedDifferent = $differentRequest
            ->withHeader(
                'Signature-Input',
                $signed->getHeaderLine('Signature-Input')
            )
            ->withHeader(
                'Signature',
                $signed->getHeaderLine('Signature')
            );

        $this->assertFalse($httpSignature->verify($pk, $signedDifferent));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowActuallyThrows(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('throw when missing test', $alg);

        $httpSignature = new HttpSignature();
        // Request has Signature-Input but NO Signature
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="' . $alg->value . '";created=' . time(),
            ],
            'body'
        );

        // Must throw HttpSignatureException with specific message
        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('HTTP header missing: Signature');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testMethodContinueDoesNotSkipMissingHeader(SigningAlgorithm $alg): void
    {
        $pk = self::pkFromSeed('continue vs break test', $alg);

        $httpSignature = new HttpSignature();
        // Craft request with @method before x-absent in covered components
        $request = new Request(
            'POST',
            '/test',
            [
                'Host' => 'example.com',
                'Signature-Input' =>
                    'sig1=("@method" "x-absent");alg="' . $alg->value . '";created='
                    . time(),
                'Signature' => 'sig1=:' . str_repeat('A', 86) . ':',
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage(
            'Covered component header missing: x-absent'
        );
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testDefaultTimeoutExactBoundary(SigningAlgorithm $alg): void
    {
        if (!extension_loaded('pqcrypto')) {
            $this->markTestSkipped('timeout tests are flakey');
        }
        $sk = self::skFromSeed('default timeout exact', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // Let's ensure the signing time doesn't make it invalid
        $start = microtime(true);
        $httpSignature->sign($sk, $request, ['@method', 'host'], 'key');
        $diff = microtime(true) - round($start, 2);

        // Exactly 300 seconds ago should pass (boundary)
        $created = (int) floor(microtime(true) - 300.0 - $diff);
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $created);
        $this->assertTrue(
            $httpSignature->verify($pk, $signedRequest),
            'Signature created exactly 300 seconds ago should be valid'
        );

        // 301 seconds ago should fail
        $created2 = time() - 301;
        $signedRequest2 = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $created2);
        $this->assertFalse(
            $httpSignature->verify($pk, $signedRequest2),
            'Signature created 301 seconds ago should be invalid'
        );
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignatureParamsExtractionCorrectness(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('params extraction correctness', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'my-key');

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');

        // Verify the format is correct
        $this->assertMatchesRegularExpression(
            '/^sig1=\("@method" "host"\);alg="' . $alg->value . '";keyid="my-key";created=\d+$/',
            $signatureInput
        );

        // The signature should verify
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));

        // Test with a wrong signature (Ed25519 only — ML-DSA-44 throws on structurally invalid sigs)
        if ($alg === SigningAlgorithm::ED25519) {
            $badRequest = new Request(
                'POST',
                '/test',
                [
                    'Host' => 'example.com',
                    'Signature-Input' => 'sig1=("@method" "host");alg="ed25519";created=' . time(),
                    'Signature' => 'sig1=:' . str_repeat('A', 86) . ':',
                ],
                'body'
            );
            $this->assertFalse($httpSignature->verify($pk, $badRequest));
        }
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignatureExtractionUsesCorrectCaptureGroup(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('capture group test', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $signed = $httpSignature->sign($sk, $request, ['@method'], 'key');

        // Verify signature format: sig1=:BASE64:
        $signatureHeader = $signed->getHeaderLine('Signature');
        $this->assertMatchesRegularExpression('/^sig1=:[A-Za-z0-9+\/=_-]+:$/', $signatureHeader);

        // The signature must verify
        $this->assertTrue($httpSignature->verify($pk, $signed));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testSignatureMatchesUsesGroup1Not0(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('matches group 1', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $signed = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key');
        $this->assertTrue($httpSignature->verify($pk, $signed));

        $signatureHeader = $signed->getHeaderLine('Signature');
        $this->assertStringStartsWith('sig1=:', $signatureHeader);
        $this->assertStringEndsWith(':', $signatureHeader);
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testKnownAnswerSignatureWithAllHeaders(): void
    {
        // Deterministic key from fixed seed (32 bytes of 0x42)
        $seed = str_repeat("\x42", 32);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair), SigningAlgorithm::ED25519);

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/inbox', ['Host' => 'example.com']);

        $created = 1700000000;
        $signed = $httpSignature->sign($sk, $request, ['@method', '@path', 'host'], 'key1', $created);

        // Verify Signature-Input format
        $expectedInput = 'sig1=("@method" "@path" "host");alg="ed25519";keyid="key1";created=1700000000';
        $this->assertSame($expectedInput, $signed->getHeaderLine('Signature-Input'));

        // Manually compute expected signature base
        $expectedSignatureBase = implode("\n", [
            '"@method": post',
            '"@path": /inbox',
            '"host": example.com',
            '"@signature-params": ("@method" "@path" "host");alg="ed25519";keyid="key1";created=1700000000'
        ]);

        // Sign manually to get expected signature
        $expectedSignatureBytes = sodium_crypto_sign_detached(
            $expectedSignatureBase,
            sodium_crypto_sign_secretkey($keypair)
        );
        $expectedSignature = 'sig1=:' . Base64::encode($expectedSignatureBytes) . ':';

        // This assertion catches Continue_→Break_ mutations
        $this->assertSame(
            $expectedSignature,
            $signed->getHeaderLine('Signature'),
            'Signature must match known answer computed with all headers included'
        );
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws SodiumException
     */
    public function testKnownAnswerMldsa44WireVector(): void
    {
        $seed = str_repeat("\x45", 32);
        $sk = new SecretKey($seed, SigningAlgorithm::MLDSA44);
        $pk = $sk->getPublicKey();

        $expectedPublicKey = '8/Ud04MLtWJ5XWhbMoQPw6/rLmykKA47B1RMT1L44Wn8H+ug0FhCRkuL9vCxZ26C9nwsnrNt9CP/acTQswDZ0y38BbPUpOErHMV53AMnHSzRqyY7xWujlt+m0G98fjjhVSSgjab7kG86bf9JmyxsQIWdrINH49joDQyYuf46zRIMDb/y4dKlD08xj/KLwLrWXama5j0WcM1W9MudY6GyOyTd9IAG6Sm1L6eBUP3kbCrKva55Ixviot5CyT88nG0VCOpYrWpMGJa2nh4BBShnBsFFpVtfi3O4C9z0bNISo5Tn+wJSqNTxZFlGn6KtjN7WZU2OyVfWKyu0DzNbcMHFtto3vDuDspiV1dxsfdxtAmQgByncX3RDPMDuVvvOCrvo6KSVnB+Z0jLEaFyN5xMiaAgHIsfjiyyduL71zL+JuGDG7FqYqBriz37d9vp0gj0SWb1yJ+WjQuzhcKcuuGY1MjeANrCYmpcHjmm+KVs+ayH8TuBalol7mFLPJY89qKhptnUl5j1xIk9Zusc9yzMjyAORQfMm5VBK9DbYlk+pHqe4vIDaBrCVl3nwn3Qp1H4Ey3nu5T7jE54CoIQnw73h1NHwzmykorr9UQXqN2k+x8TP5rehmgzS4Nh7IleE2e8K8xjxZZIVUIHicBxwofFWlLbqvwivqTYZAK4h0UAD9vzGeY/s0guy/TdRPOFP4CIhYbMFGLQrw0Eoa0Dl5ErMm8eIPLqA9X2K4Ip3PzJhYqt5MFzVpqsJ9SJAeJGr/rLqYCW4U6U4VEuy65nIbtoURDlJpdROkn0sIutYn45N9451xGY3x9BFVKXnZwRh6pkno+CHiJV5QC1xrHQn98rDatANCodgghhFq3WdjHz8Z6uWJsiyg4LXlBLEwJEqTRhXCx7w/Sdbiz/ZF5Y0gQBaZ8Ai1jNVxy+0ZIoCb5z67RdtyMlt++4KpgZlIc/6oV4rvmOTx0ulVjNcQhHS6h3aaNZPc2UzzYmHPIQ8n0AJY/mCE2HRk4w5JyCSPQzSwZRnwPH7oSCC/FTFGSq+5JX8KgL3p+GUOd6qmF2EqhISbuKKn0adIBTrvJxe6pBsfmGSXgMV6vLHllBBCoJhZrUioHM6b9bPW9W6427iY8jqmyPbAEqQcUGS7hNpsmTNaTrdu5FuU63OAxNFuxxGkXtCuzUjGdek47dB4viXLlOSJQFm0idLHt/DcIepevSFKFflajL6dh6ULHiiQWjxpDOODdzXyZCFt7PZ6QhKL2HXFHxZPEolZR+rkTlGXdhYBFm2t2l5u1CaTSvZkFmpGE5jsFB0zUU+1XdaczaKyDe2SvKSr8g2wbllIRiWnPIyBEuEBSdL0UtNkrZclm3rTspqfeOru796u7yRDAXlbki9mFCgqHSd729NiS66SwgcrYWtL866tbxvl4bG05BfkuCC2ZXX4AbCp+ikk0nndnfpRny5O4qGLHKjWWX3Q0AN+0PAnsJuWE0yGmRav5hzdJlO+RKaD+9NcX8Mx9IlYbqlLg6aYz1Cwp9qiKraqWv43w/LBEyRmW45s0Kg+f1vMH3BPAvXrDUND6eq3s134LgYF99lc7RcuynlPHvnVVoDRkECLZaCXTVhYM/Wq5Tv/kNiY8Wt7/Wq2lZvD8z0JWQDkIKe/Wl91Eo+fQ6XyO+kEa0mvc7XhdOSbggPsfxs4z8gZwo/tGYpxsIUbPLC0pCejYvIvAglukRAvOD/c7YPhtko8SA0yZkLHWTdT7jXbPvmVA==';
        $expectedSignatureInput =
            'sig1=("@method" "@path" "host" "date");alg="ml-dsa-44";'
            . 'keyid="test-key-mldsa44";created=1783368000';
        $expectedSignatureBase = implode("\n", [
            '"@method": get',
            '"@path": /foo',
            '"host": example.com',
            '"date": Mon, 06 Jul 2026 20:00:00 GMT',
            '"@signature-params": ("@method" "@path" "host" "date");'
            . 'alg="ml-dsa-44";keyid="test-key-mldsa44";created=1783368000',
        ]);
        $expectedSignature = <<<'B64'
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
B64;

        $this->assertSame($expectedPublicKey, Base64::encode($pk->getBytes()));
        $this->assertSame(2420, strlen(Base64::decode($expectedSignature)));
        $this->assertTrue($pk->verify(Base64::decode($expectedSignature), $expectedSignatureBase));

        $httpSignature = new HttpSignature();
        $request = new Request('GET', '/foo?param=Value&Pet=dog', [
            'Host' => 'example.com',
            'Date' => 'Mon, 06 Jul 2026 20:00:00 GMT',
        ]);
        $signed = $httpSignature->sign(
            $sk,
            $request,
            ['@method', '@path', 'host', 'date'],
            'test-key-mldsa44',
            1783368000
        );

        $this->assertSame($expectedSignatureInput, $signed->getHeaderLine('Signature-Input'));
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testKnownAnswerMethodThenPath(): void
    {
        $seed = str_repeat("\x43", 32);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair), SigningAlgorithm::ED25519);

        $httpSignature = new HttpSignature();
        $request = new Request('GET', '/api/v1/resource', ['Host' => 'api.test']);

        $created = 1700000001;
        $signed = $httpSignature->sign($sk, $request, ['@method', '@path'], 'test-key', $created);

        $expectedSignatureBase = implode("\n", [
            '"@method": get',
            '"@path": /api/v1/resource',
            '"@signature-params": ("@method" "@path");alg="ed25519";keyid="test-key";created=1700000001'
        ]);
        $expectedSignatureBytes = sodium_crypto_sign_detached(
            $expectedSignatureBase,
            sodium_crypto_sign_secretkey($keypair)
        );
        $expectedSignature = 'sig1=:' . Base64::encode($expectedSignatureBytes) . ':';

        $this->assertSame(
            $expectedSignature,
            $signed->getHeaderLine('Signature'),
            '@path must be included after @method (continue not break)'
        );
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testKnownAnswerPathThenHost(): void
    {
        $seed = str_repeat("\x44", 32);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair), SigningAlgorithm::ED25519);

        $httpSignature = new HttpSignature();
        $request = new Request('DELETE', '/users/123', ['Host' => 'admin.example.org']);

        $created = 1700000002;
        $signed = $httpSignature->sign($sk, $request, ['@path', 'host'], 'admin-key', $created);

        // Expected signature base with BOTH @path and host
        $expectedSignatureBase = implode("\n", [
            '"@path": /users/123',
            '"host": admin.example.org',
            '"@signature-params": ("@path" "host");alg="ed25519";keyid="admin-key";created=1700000002'
        ]);

        $expectedSignatureBytes = sodium_crypto_sign_detached(
            $expectedSignatureBase,
            sodium_crypto_sign_secretkey($keypair)
        );
        $expectedSignature = 'sig1=:' . Base64::encode($expectedSignatureBytes) . ':';

        $this->assertSame(
            $expectedSignature,
            $signed->getHeaderLine('Signature'),
            'host must be included after @path (continue not break)'
        );
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyAcceptsMldsa44Hyphenated(): void
    {
        $sk = self::skFromSeed('mldsa-44 hyphen', SigningAlgorithm::ED25519);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        $signed = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key');
        $sigInput = str_replace('alg="ed25519"', 'alg="mldsa-44"', $signed->getHeaderLine('Signature-Input'));
        $crafted = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => $sigInput,
                'Signature' => $signed->getHeaderLine('Signature'),
            ],
            'body'
        );
        $this->assertFalse($httpSignature->verify($pk, $crafted));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyAcceptsLegacyMldsa44Algorithm(): void
    {
        $sk = self::skFromSeed('legacy mldsa44 http alg', SigningAlgorithm::MLDSA44);
        $pk = $sk->getPublicKey();
        $created = time();
        $signatureInput = 'sig1=("@method" "host");alg="mldsa44";keyid="key";created=' . $created;
        $signatureBase = implode("\n", [
            '"@method": post',
            '"host": example.com',
            '"@signature-params": ("@method" "host");alg="mldsa44";keyid="key";created=' . $created,
        ]);
        $signature = Base64::encode($sk->sign($signatureBase));

        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => $signatureInput,
                'Signature' => 'sig1=:' . $signature . ':',
            ],
            'body'
        );

        $httpSignature = new HttpSignature();
        $this->assertTrue($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyEmptyCoveredComponents(): void
    {
        $sk = self::skFromSeed('empty components', SigningAlgorithm::ED25519);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        $signed = $httpSignature->sign($sk, $request, ['host'], 'key');
        // Sign nothing
        $sigInput = 'sig1=();alg="ed25519";created=' . time();
        $crafted = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => $sigInput,
                'Signature' => $signed->getHeaderLine('Signature'),
            ],
            'body'
        );
        $this->expectException(HttpSignatureException::class);
        $httpSignature->verifyThrow($pk, $crafted);
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("signingAlgorithmProvider")]
    public function testSignEmptyCoveredThrows(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('sign rejects empty covered', $alg);
        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage(
            'At least one covered component is required when signing'
        );
        $httpSignature->sign($sk, $request, [], 'key');
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("signingAlgorithmProvider")]
    public function testSignAndVerifyStatusOnResponse(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('status component', $alg);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $response = new Response(200, ['Content-Type' => 'application/json'], '{}');

        $signed = $httpSignature->sign(
            $sk,
            $response,
            ['@status', 'content-type'],
            'key'
        );
        /** @var Response $signed */
        $this->assertTrue($httpSignature->verify($pk, $signed));

        $sigInput = $signed->getHeaderLine('Signature-Input');
        $this->assertStringStartsWith('sig1=("@status" "content-type");', $sigInput);

        // Flipping the status invalidates the signature (binding property).
        $tamperedStatus = $signed->withStatus(500);
        $this->assertFalse($httpSignature->verify($pk, $tamperedStatus));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("ed25519OnlyProvider")]
    public function testVerifyThrowStatusOnRequest(SigningAlgorithm $alg): void
    {
        $sk = self::skFromSeed('status on request', $alg);
        $pk = $sk->getPublicKey();

        // Sign against a response, then replay the signed headers onto a request message.
        // The verifier must refuse because @status is response-only.
        $httpSignature = new HttpSignature();
        $response = new Response(200, ['Content-Type' => 'application/json'], '{}');
        $signed = $httpSignature->sign($sk, $response, ['@status'], 'key');
        $crafted = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => $signed->getHeaderLine('Signature-Input'),
                'Signature' => $signed->getHeaderLine('Signature'),
            ],
            'body'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Covered component "@status" requires a response message');
        $httpSignature->verifyThrow($pk, $crafted);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testSignatureBaseIncludesHeaderAfterStatus(): void
    {
        $sk = self::skFromSeed('status continue base', SigningAlgorithm::ED25519);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $response = new Response(200, ['Content-Type' => 'application/json'], '{}');

        $signed = $httpSignature->sign(
            $sk,
            $response,
            ['@status', 'content-type'],
            'key'
        );

        /** @var Response $signed */
        $tampered = $signed->withHeader('Content-Type', 'text/plain');
        $this->assertFalse(
            $httpSignature->verify($pk, $tampered),
            'content-type listed after @status must be covered by signature'
        );
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyChecksHeadersListedAfterStatus(): void
    {
        $sk = self::skFromSeed('status continue verify', SigningAlgorithm::ED25519);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $response = new Response(
            200,
            ['Content-Type' => 'application/json'],
            '{}'
        );
        $signed = $httpSignature->sign(
            $sk,
            $response,
            ['@status', 'x-absent'],
            'key'
        );

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('Covered component header missing: x-absent');
        $httpSignature->verifyThrow($pk, $signed);
    }
}
