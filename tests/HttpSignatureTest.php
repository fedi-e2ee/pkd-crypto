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
        $pk = new \FediE2EE\PKD\Crypto\PublicKey(sodium_crypto_sign_publickey($keypair));

        $httpSignature = new HttpSignature();
        $request = new Request('POST', '/foo', ['Host' => 'example.com'], 'body');

        // No Signature-Input header
        $this->assertFalse($httpSignature->verify($pk, $request));
    }

    /**
     * Test verification fails when Signature header is missing
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

        // Has Signature-Input but no Signature header
        $this->assertFalse($httpSignature->verify($pk, $request));
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
}
