<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    PublicKey,
    Revocation,
    SecretKey
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use PhpFuzzer\Config;
use RuntimeException;
use SodiumException;
use TypeError;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    $revocation = new Revocation();

    // Test decode() with arbitrary input (as base64url-encoded)
    try {
        $encoded = Base64UrlSafe::encodeUnpadded($input);
        $revocation->decode($encoded);
    } catch (CryptoException|TypeError) {
        // Expected for most inputs - token must be exactly 153 bytes
    }

    // Test decode() with arbitrary base64url string directly
    try {
        $revocation->decode($input);
    } catch (CryptoException|TypeError) {
        // Expected for invalid base64url or wrong length
    }

    // Test verifyRevocationToken() with arbitrary input
    try {
        $encoded = Base64UrlSafe::encodeUnpadded($input);
        $revocation->verifyRevocationToken($encoded);
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for most inputs
    }

    // Need at least 32 bytes for a keypair
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

    // Test round-trip: generate token and verify it
    try {
        $token = $revocation->revokeThirdParty($sk);
        $valid = $revocation->verifyRevocationToken($token);
        if (!$valid) {
            throw new RuntimeException('Round-trip revocation token verification failed');
        }

        // Verify with explicit public key
        $valid2 = $revocation->verifyRevocationToken($token, $pk);
        if (!$valid2) {
            throw new RuntimeException('Round-trip with explicit pk failed');
        }
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }

    // Test verification with wrong public key
    try {
        $token = $revocation->revokeThirdParty($sk);

        // Create different keypair
        $otherKeypair = sodium_crypto_sign_seed_keypair(hash('sha512', $keyBytes, true));
        $otherPk = new PublicKey(sodium_crypto_sign_publickey($otherKeypair));

        try {
            $revocation->verifyRevocationToken($token, $otherPk);
            throw new RuntimeException('Wrong public key should not verify');
        } catch (CryptoException) {
            // Expected - mismatched public key
        }
    } catch (NotImplementedException|SodiumException|TypeError) {
        // Expected
    }

    // Test decode() output structure
    try {
        $token = $revocation->revokeThirdParty($sk);
        [$decodedPk, $signed, $signature] = $revocation->decode($token);

        assert($decodedPk instanceof PublicKey);
        assert(is_string($signed));
        assert(is_string($signature));
        assert(strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES);
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }

    // Test with tampered token (various tampering strategies)
    try {
        $token = $revocation->revokeThirdParty($sk);
        $decoded = Base64UrlSafe::decodeNoPadding($token);

        if (strlen($decoded) >= 153) {
            // Tamper with version header (first 8 bytes)
            $tampered1 = "\x00\x00\x00\x00\x00\x00\x00\x00" . substr($decoded, 8);
            try {
                $revocation->verifyRevocationToken(Base64UrlSafe::encodeUnpadded($tampered1));
                throw new RuntimeException('Should reject invalid version header');
            } catch (CryptoException) {
                // Expected
            }

            // Tamper with revocation constant (bytes 8-56)
            $tampered2 = substr($decoded, 0, 8) . str_repeat("\x00", 49) . substr($decoded, 57);
            try {
                $revocation->verifyRevocationToken(Base64UrlSafe::encodeUnpadded($tampered2));
                throw new RuntimeException('Should reject invalid revocation constant');
            } catch (CryptoException) {
                // Expected
            }

            // Tamper with public key (bytes 57-88)
            $tampered3 = substr($decoded, 0, 57) . str_repeat("\xFF", 32) . substr($decoded, 89);
            try {
                $revocation->verifyRevocationToken(Base64UrlSafe::encodeUnpadded($tampered3));
                throw new RuntimeException('Should reject tampered public key');
            } catch (CryptoException) {
                // Expected - mismatched public key
            }

            // Tamper with signature (bytes 89-152)
            $tampered4 = substr($decoded, 0, 89) . str_repeat("\x00", 64);
            try {
                $revocation->verifyRevocationToken(Base64UrlSafe::encodeUnpadded($tampered4));
                throw new RuntimeException('Should reject invalid signature');
            } catch (CryptoException|NotImplementedException|SodiumException) {
                // Expected - signature verification failure
            }

            // Truncate token
            $tampered5 = substr($decoded, 0, 100);
            try {
                $revocation->verifyRevocationToken(Base64UrlSafe::encodeUnpadded($tampered5));
                throw new RuntimeException('Should reject truncated token');
            } catch (CryptoException) {
                // Expected - too short
            }

            // Extend token with extra bytes
            $tampered6 = $decoded . str_repeat("\xFF", 32);
            try {
                // This might actually verify if signature still checks out
                // The extra bytes are ignored
                $revocation->verifyRevocationToken(Base64UrlSafe::encodeUnpadded($tampered6));
            } catch (CryptoException|NotImplementedException|SodiumException) {
                // Also acceptable
            }
        }
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }

    // Test with various lengths around the boundary (153 bytes)
    for ($len = 150; $len <= 156; $len++) {
        try {
            $testInput = str_pad(substr($input, 0, min($len, strlen($input))), $len, "\x00");
            $encoded = Base64UrlSafe::encodeUnpadded($testInput);
            $revocation->decode($encoded);
        } catch (CryptoException|TypeError) {
            // Expected for lengths != 153
        }
    }

    // Test decode with well-formed structure but invalid signature
    try {
        $version = 'FediPKD1'; // 8 bytes
        $constant = str_repeat("\xFE", 32) . 'revoke-public-key'; // 49 bytes
        $pkBytes = $pk->getBytes(); // 32 bytes
        $fakeSignature = substr($input, 0, min(64, strlen($input)));
        $fakeSignature = str_pad($fakeSignature, 64, "\x00"); // 64 bytes

        $constructed = $version . $constant . $pkBytes . $fakeSignature;
        assert(strlen($constructed) === 153);

        $token = Base64UrlSafe::encodeUnpadded($constructed);

        try {
            $revocation->verifyRevocationToken($token);
            // Extremely unlikely to succeed (1 in 2^256 chance)
        } catch (CryptoException|NotImplementedException|SodiumException) {
            // Expected - signature verification failure
        }
    } catch (TypeError) {
        // Expected for edge cases
    }

    // Test that decode extracts correct components
    try {
        $token = $revocation->revokeThirdParty($sk);
        [$extractedPk, $signed, $signature] = $revocation->decode($token);

        // Verify the extracted public key matches
        if ($extractedPk->toString() !== $pk->toString()) {
            throw new RuntimeException('Decoded public key mismatch');
        }

        // Verify the signed portion is exactly 89 bytes (version + constant + pk)
        if (strlen($signed) !== 89) {
            throw new RuntimeException('Signed portion should be 89 bytes');
        }

        // Verify signature is exactly 64 bytes
        if (strlen($signature) !== 64) {
            throw new RuntimeException('Signature should be 64 bytes');
        }
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }
});
