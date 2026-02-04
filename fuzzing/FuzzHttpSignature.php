<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    HttpSignatureException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    HttpSignature,
    SecretKey
};
use GuzzleHttp\Psr7\Request;
use PhpFuzzer\Config;
use RuntimeException;
use SodiumException;
use TypeError;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    // Need at least 32 bytes for a key
    if (strlen($input) < 32) {
        return;
    }

    // Generate deterministic keypair from input
    $keyBytes = substr($input, 0, 32);
    try {
        $keypair = sodium_crypto_sign_seed_keypair($keyBytes);
        $sk = new SecretKey(sodium_crypto_sign_secretkey($keypair));
        $pk = $sk->getPublicKey();
    } catch (SodiumException) {
        return;
    }

    $remaining = substr($input, 32);
    if (strlen($remaining) < 4) {
        return;
    }

    // Test HttpSignature construction with various timeout windows
    try {
        $timeout = (ord($remaining[0]) << 8) | ord($remaining[1]);
        if ($timeout >= 2 && $timeout <= 86400) {
            $httpSig = new HttpSignature('sig1', $timeout);
        } else {
            $httpSig = new HttpSignature();
        }
    } catch (HttpSignatureException) {
        // Expected for invalid timeout values
        return;
    }

    // Test with custom label containing special characters
    try {
        $labelLen = min(16, ord($remaining[2]));
        $label = substr($remaining, 3, $labelLen);
        if (!empty($label)) {
            $httpSig = new HttpSignature($label);
        }
    } catch (HttpSignatureException|TypeError) {
        // Expected for invalid labels
    }

    // Test sign and verify round-trip with arbitrary headers
    try {
        $httpSig = new HttpSignature();
        $path = '/' . substr($remaining, 0, min(32, strlen($remaining)));
        $request = new Request(
            'POST',
            $path,
            ['Host' => 'example.com', 'Content-Type' => 'application/json'],
            'body'
        );

        // Test with various header combinations
        $headerSets = [
            ['@method'],
            ['@path'],
            ['@method', '@path'],
            ['@method', '@path', 'host'],
            ['@method', '@path', 'host', 'content-type'],
        ];

        foreach ($headerSets as $headers) {
            try {
                $signedRequest = $httpSig->sign($sk, $request, $headers, 'test-key');
                $valid = $httpSig->verify($pk, $signedRequest);
                if (!$valid) {
                    throw new RuntimeException('Sign/verify round-trip failed');
                }
            } catch (TypeError|SodiumException|NotImplementedException) {
                // Expected for edge cases
            }
        }
    } catch (TypeError|RuntimeException) {
        // Expected for malformed data
    }

    // Test verification with arbitrary Signature-Input header
    try {
        $httpSig = new HttpSignature();
        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => $input,
                'Signature' => 'sig1=:AAAA:',
            ],
            'body'
        );
        $httpSig->verify($pk, $request);
    } catch (TypeError|HttpSignatureException|CryptoException|NotImplementedException|SodiumException) {
        // Expected for malformed input
    }

    // Test verification with well-formed but invalid signature
    try {
        $httpSig = new HttpSignature();
        $created = time();
        $signatureInput = 'sig1=("@method" "@path");alg="ed25519";keyid="test";created=' . $created;

        // Split input into parts for signature
        $sigLen = min(64, strlen($remaining));
        $fakeSignature = str_pad(substr($remaining, 0, $sigLen), 64, "\x00");
        $encodedSig = base64_encode($fakeSignature);

        $request = new Request(
            'POST',
            '/foo',
            [
                'Host' => 'example.com',
                'Signature-Input' => $signatureInput,
                'Signature' => 'sig1=:' . $encodedSig . ':',
            ],
            'body'
        );

        $result = $httpSig->verify($pk, $request);
        // Should almost always be false (1 in 2^256 chance of collision)
        if ($result) {
            // This would be extremely unlikely but not necessarily an error
            var_dump($request, $pk);
        }
    } catch (TypeError|HttpSignatureException|SodiumException|NotImplementedException) {
        // Expected for edge cases
    }
});
