<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\HttpSignatureException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\HttpSignature;
use FediE2EE\PKD\Crypto\SecretKey;
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
}
