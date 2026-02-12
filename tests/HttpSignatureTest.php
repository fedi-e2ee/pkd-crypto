<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    HttpSignatureException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    HttpSignature,
    PublicKey,
    SecretKey
};
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use ParagonIE\ConstantTime\Base64;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(HttpSignature::class)]
class HttpSignatureTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignAndVerify(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit test case for fedi-e2ee/pkd-client')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret);
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], '{"hello": "world"}');

        $signedRequest = $httpSignature->sign($sk, $request, ['@method', '@path', 'host'], 'test-key-a');

        $this->assertTrue($signedRequest->hasHeader('Signature-Input'));
        $this->assertTrue($signedRequest->hasHeader('Signature'));

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');
        $this->assertStringStartsWith('sig1=("@method" "@path" "host");', $signatureInput);
        $this->assertStringContainsString(';alg="ed25519"', $signatureInput);
        $this->assertStringContainsString(';keyid="test-key-a"', $signatureInput);
        $this->assertMatchesRegularExpression('/;created=\d+/', $signatureInput);


        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
        $this->assertTrue($httpSignature->verifyThrow($pk, $signedRequest));
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
     * Test verification fails when Signature-Input header is missing
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyMissingSignatureInput(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test key')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // No Signature-Input header
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyMissingSignature(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test key')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="ed25519";created=1234567890'
            ],
            'body'
        );
        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('HTTP header missing: Signature');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * Test verifyThrow throws when headers are missing
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowMissingHeaders(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test key')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        $this->expectException(HttpSignatureException::class);
        $this->expectExceptionMessage('HTTP header missing: Signature-Input');
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * Test verification with different label
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignAndVerifyCustomLabel(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('custom label test')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret);
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
     * Test verification fails with wrong public key
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyWrongKey(): void
    {
        $keypair1 = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('key 1')
        );
        $sk1 = new SecretKey(sodium_crypto_sign_secretkey($keypair1));

        $keypair2 = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('key 2')
        );
        $pk2 = new PublicKey(sodium_crypto_sign_publickey($keypair2));

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');
        $signedRequest = $httpSignature->sign($sk1, $request, ['@method', 'host'], 'key-1');

        // Verify with wrong key should fail
        $this->assertFalse($httpSignature->verify($pk2, $signedRequest));
    }

    /**
     * Test verification fails when signature is expired
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyExpiredSignature(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('expired test')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret);
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
     */
    public function testVerifyNonNumericCreated(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('non-numeric created test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="ed25519";created=not-a-number',
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );

        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * Test verification at exactly the timeout boundary.
     * This kills the GreaterThan mutation (> to >=).
     */
    public function testVerifyExactTimeoutBoundary(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('boundary test')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret);
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
     */
    public function testLabelWithRegexSpecialCharacters(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('regex label test')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $sk = new SecretKey($secret);
        $pk = $sk->getPublicKey();

        // Label with characters that need escaping in regex
        $httpSignature = new HttpSignature('sig.test+1');
        $request = new Request('GET', '/test', ['Host' => 'example.org']);
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key-id');

        $this->assertTrue($httpSignature->verify($pk, $signedRequest));
    }

    /**
     * Test verification throws when Signature-Input cannot be parsed.
     */
    public function testVerifyInvalidSignatureInputFormat(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('invalid format test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testHeaderCaseNormalization(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('case normalization test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifySignatureLabelNotFound(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('label not found test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        // Create a signature using label "sig1" but verify with "sig2"
        $httpSignature = new HttpSignature('sig2');
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig2=("@method");alg="ed25519";created=' . time(),
                'Signature' => 'sig1=:AAAA:', // Wrong label
            ],
            'body'
        );

        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowSignatureLabelNotFound(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('throw label test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature('mysig');
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'mysig=("@method");alg="ed25519";created=' . time(),
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyUnsupportedAlgorithm(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('unsupported algo test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowUnsupportedAlgorithm(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('unsupported algo throw')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

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
        $httpSignature->verifyThrow($pk, $request);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowMissingAlgorithm(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing algo throw')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowMissingCreated(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing created throw')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="ed25519"',
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowExpiredSignature(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('expired throw test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowMissingSignatureHeader(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing sig header')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="ed25519";created=' . time(),
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignWithMixedCaseHeaders(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('mixed case headers')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMethodIsLowercaseInSignatureBase(): void
    {
        $keypair1 = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('method case test 1')
        );
        $keypair2 = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('method case test 2')
        );
        $sk1 = new SecretKey(sodium_crypto_sign_secretkey($keypair1));
        $sk2 = new SecretKey(sodium_crypto_sign_secretkey($keypair2));
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

        $this->assertSame(
            $signed2->getHeaderLine('Signature'),
            $signed3->getHeaderLine('Signature'),
            'Method case should be normalized'
        );
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignWithSingleHeader(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('single header test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignWithPathOnly(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('path only test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignatureExtractionExactLabel(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('exact label test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature('sig1');
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="ed25519";created=' . time(),
                'Signature' => 'sig10=:AAAA:, sig11=:BBBB:',
            ],
            'body'
        );
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMethodLowercasedInBase(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('method lowercase test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testDefaultTimeoutIs300(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('default timeout test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        $created = time() - 299;
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $created);
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));

        $created2 = time() - 301;
        $signedRequest2 = $httpSignature->sign($sk, $request, ['@method', 'host'], 'key', $created2);
        $this->assertFalse($httpSignature->verify($pk, $signedRequest2));
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignatureParamsExtraction(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('params extraction test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $created = time();
        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'my-key-id', $created);

        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');

        // Verify all params are present
        $this->assertStringContainsString('alg="ed25519"', $signatureInput);
        $this->assertStringContainsString('keyid="my-key-id"', $signatureInput);
        $this->assertStringContainsString('created=' . $created, $signatureInput);
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMissingSignatureInputWithSignaturePresent(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing sig input test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testUnknownHeadersAreSkipped(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('unknown headers test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMethodLowercasedForConsistency(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('method lowercase consistency')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));

        $httpSignature = new HttpSignature();
        $created = time();

        // POST should produce same signature as post
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testPathInSignatureBase(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('path signature test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request1 = new Request('GET', '/path1', ['Host' => 'example.com']);
        $request2 = new Request('GET', '/path2', ['Host' => 'example.com']);

        $created = time();
        $signed1 = $httpSignature->sign($sk, $request1, ['@path'], 'key', $created);
        $signed2 = $httpSignature->sign($sk, $request2, ['@path'], 'key', $created);
        $this->assertNotSame(
            $signed1->getHeaderLine('Signature'),
            $signed2->getHeaderLine('Signature')
        );
        $this->assertTrue($httpSignature->verify($pk, $signed1));
        $this->assertTrue($httpSignature->verify($pk, $signed2));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testCustomTimeoutWindow(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('custom timeout window')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMissingRequiredHeaderFails(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing header test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method" "x-custom-missing");alg="ed25519";created=' . time(),
                'Signature' => 'sig1=:' . str_repeat('A', 86) . ':',
            ],
            'body'
        );
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testForeachProcessesAllHeaders(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('foreach all headers')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMethodDoesNotBreakLoop(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('method does not break loop')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
        $this->assertNotSame(
            $signedWithAll->getHeaderLine('Signature'),
            $signedMethodOnly->getHeaderLine('Signature'),
            '@method must not break out of the loop - @path and host must be included'
        );
        $this->assertTrue($httpSignature->verify($pk, $signedWithAll));
        $this->assertTrue($httpSignature->verify($pk, $signedMethodOnly));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testPathDoesNotBreakLoop(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('path does not break loop')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
        $this->assertNotSame(
            $signedWithAll->getHeaderLine('Signature'),
            $signedPathOnly->getHeaderLine('Signature'),
            '@path must not break out of the loop - host and x-custom must be included'
        );

        $this->assertTrue($httpSignature->verify($pk, $signedWithAll));
        $this->assertTrue($httpSignature->verify($pk, $signedPathOnly));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMissingCoveredHeaderRejectsVerify(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing header skipped')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowMissingCoveredHeader(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('missing header throw')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyRejectsTamperedHeaderValue(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('tampered header test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyThrowActuallyThrows(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('throw when missing test')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        // Request has Signature-Input but NO Signature
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => 'sig1=("@method");alg="ed25519";created=' . time(),
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testDefaultTimeoutExactBoundary(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('default timeout exact')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // Exactly 300 seconds ago should pass (boundary)
        $created = time() - 300;
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
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignatureParamsExtractionCorrectness(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('params extraction correctness')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $signedRequest = $httpSignature->sign($sk, $request, ['@method', 'host'], 'my-key');

        // The signature-input should be: sig1=("@method" "host");alg="ed25519";keyid="my-key";created=...
        $signatureInput = $signedRequest->getHeaderLine('Signature-Input');

        // Verify the format is correct
        $this->assertMatchesRegularExpression(
            '/^sig1=\("@method" "host"\);alg="ed25519";keyid="my-key";created=\d+$/',
            $signatureInput
        );

        // The signature should verify - this ensures the params extraction works
        $this->assertTrue($httpSignature->verify($pk, $signedRequest));

        // Now test with a malformed signature-input where params extraction would fail
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

        // This should fail verification (wrong signature) but not error
        $this->assertFalse($httpSignature->verify($pk, $badRequest));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignatureExtractionUsesCorrectCaptureGroup(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('capture group test')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/test', ['Host' => 'example.com'], 'body');

        $signed = $httpSignature->sign($sk, $request, ['@method'], 'key');

        // Verify signature format: sig1=:BASE64:
        $signatureHeader = $signed->getHeaderLine('Signature');
        $this->assertMatchesRegularExpression('/^sig1=:[A-Za-z0-9+\/]+=*:$/', $signatureHeader);

        // The signature must verify
        $this->assertTrue($httpSignature->verify($pk, $signed));
    }

    /**
     * @throws CryptoException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignatureMatchesUsesGroup1Not0(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('matches group 1')
        );
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
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
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testKnownAnswerSignatureWithAllHeaders(): void
    {
        // Deterministic key from fixed seed (32 bytes of 0x42)
        $seed = str_repeat("\x42", 32);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));

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
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testKnownAnswerMethodThenPath(): void
    {
        $seed = str_repeat("\x43", 32);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));

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
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testKnownAnswerPathThenHost(): void
    {
        $seed = str_repeat("\x44", 32);
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));

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
}
