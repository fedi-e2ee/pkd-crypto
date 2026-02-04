<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    EncodingException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    PublicKey,
    SecretKey
};
use PhpFuzzer\Config;
use RuntimeException;
use SodiumException;
use TypeError;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    try {
        $pk = new PublicKey($input);
        assert($pk->getAlgo() === 'ed25519');
        assert(strlen($pk->getBytes()) === 32);
    } catch (CryptoException|TypeError) {
        // Expected for inputs that are not exactly 32 bytes
    }

    try {
        new PublicKey($input, 'unknown-algo');
        throw new RuntimeException('Should reject unknown algorithm');
    } catch (CryptoException) {
        // Expected
    }

    try {
        $sk = new SecretKey($input);
        assert($sk->getAlgo() === 'ed25519');
    } catch (CryptoException|TypeError) {
        // Expected for inputs that are not exactly 64 bytes
    }

    try {
        new SecretKey($input, 'unknown-algo');
        throw new RuntimeException('Should reject unknown algorithm');
    } catch (CryptoException) {
        // Expected
    }

    if (strlen($input) < 32) {
        return;
    }

    try {
        $pkBytes = substr($input, 0, 32);
        $pk = new PublicKey($pkBytes);

        // Test toString/fromString round-trip
        $str = $pk->toString();
        $pk2 = PublicKey::fromString($str);
        if ($pk->toString() !== $pk2->toString()) {
            throw new RuntimeException('toString/fromString round-trip mismatch');
        }

        // Test PEM encoding round-trip
        $pem = $pk->encodePem();
        $pk3 = PublicKey::importPem($pem);
        if ($pk->toString() !== $pk3->toString()) {
            throw new RuntimeException('PEM round-trip mismatch');
        }

        // Test Multibase encoding round-trip
        $multibase = $pk->toMultibase();
        $pk4 = PublicKey::fromMultibase($multibase);
        if ($pk->toString() !== $pk4->toString()) {
            throw new RuntimeException('Multibase round-trip mismatch');
        }

        // Test unsafe Multibase variant
        $multibaseUnsafe = $pk->toMultibase(true);
        $pk5 = PublicKey::fromMultibase($multibaseUnsafe);
        if ($pk->toString() !== $pk5->toString()) {
            throw new RuntimeException('Multibase unsafe round-trip mismatch');
        }
    } catch (CryptoException|EncodingException|TypeError) {
        // Expected for edge cases
    }

    try {
        PublicKey::fromString($input);
    } catch (CryptoException|TypeError) {
        // Expected for malformed input
    }

    try {
        $malformedFormats = [
            'no-colon-separator',
            ':only-colon-no-algo',
            'ed25519:', // Empty key
            'ed25519:invalid-base64!!',
            'unknown-algo:' . base64_encode($input),
        ];

        foreach ($malformedFormats as $malformed) {
            try {
                PublicKey::fromString($malformed);
            } catch (CryptoException|TypeError) {
                // Expected
            }
        }
    } catch (TypeError) {
        // Expected
    }

    try {
        PublicKey::importPem($input);
    } catch (CryptoException|TypeError) {
        // Expected for most inputs
    }

    try {
        $malformedPems = [
            "-----BEGIN PUBLIC KEY-----\n" . $input . "\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\ninvalid-base64!@#$\n-----END PUBLIC KEY-----",
            "-----BEGIN PRIVATE KEY-----\n" . base64_encode($input) . "\n-----END PRIVATE KEY-----",
            "no pem markers at all",
        ];

        foreach ($malformedPems as $malformedPem) {
            try {
                PublicKey::importPem($malformedPem);
            } catch (CryptoException|TypeError) {
                // Expected
            }
        }
    } catch (TypeError) {
        // Expected
    }

    try {
        PublicKey::fromMultibase($input);
    } catch (CryptoException|EncodingException|TypeError) {
        // Expected for most inputs
    }

    try {
        $pk = new PublicKey(substr($input, 0, 32));
        $metadata = ['key' => 'value', 'number' => 42];
        $pk->setMetadata($metadata);
        $retrieved = $pk->getMetadata();
        if ($retrieved !== $metadata) {
            throw new RuntimeException('Metadata mismatch');
        }
    } catch (CryptoException|TypeError) {
        // Expected for edge cases
    }

    try {
        $pk = new PublicKey(substr($input, 0, 32));
        $str1 = $pk->toString();
        $str2 = (string) $pk;
        if ($str1 !== $str2) {
            throw new RuntimeException('__toString mismatch');
        }
    } catch (CryptoException|TypeError) {
        // Expected for edge cases
    }

    // Need at least 64 bytes for a secret key
    if (strlen($input) < 64) {
        return;
    }

    try {
        $skBytes = substr($input, 0, 64);
        $sk = new SecretKey($skBytes);

        // Test PEM encoding round-trip
        $pem = $sk->encodePem();
        $sk2 = SecretKey::importPem($pem);

        // Compare public keys to verify round-trip (can't compare secret keys directly)
        $pk1 = $sk->getPublicKey();
        $pk2 = $sk2->getPublicKey();
        if ($pk1->toString() !== $pk2->toString()) {
            throw new RuntimeException('SecretKey PEM round-trip mismatch');
        }
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }

    try {
        SecretKey::importPem($input);
    } catch (CryptoException|TypeError) {
        // Expected for most inputs
    }

    try {
        $malformedPems = [
            "-----BEGIN EC PRIVATE KEY-----\n" . $input . "\n-----END EC PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----\ninvalid-base64!@#$\n-----END EC PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----\n" . base64_encode($input) . "\n-----END PUBLIC KEY-----",
            "no pem markers",
        ];

        foreach ($malformedPems as $malformedPem) {
            try {
                SecretKey::importPem($malformedPem);
            } catch (CryptoException|TypeError) {
                // Expected
            }
        }
    } catch (TypeError) {
        // Expected
    }

    try {
        $sk = new SecretKey(substr($input, 0, 64));
        $pk = $sk->getPublicKey();
        assert($pk instanceof PublicKey);
        assert(strlen($pk->getBytes()) === 32);
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }

    try {
        $sk = new SecretKey(substr($input, 0, 64));
        $pk = $sk->getPublicKey();
        $message = substr($input, 64) ?: 'test message';

        $signature = $sk->sign($message);
        $valid = $pk->verify($signature, $message);
        if (!$valid) {
            throw new RuntimeException('Sign/verify round-trip failed');
        }

        // Test with wrong message
        $wrongMessage = $message . 'x';
        $valid2 = $pk->verify($signature, $wrongMessage);
        if ($valid2) {
            throw new RuntimeException('Should not verify with wrong message');
        }

        // Test with tampered signature
        if (strlen($signature) > 0) {
            $tamperedSig = "\x00" . substr($signature, 1);
            $valid3 = $pk->verify($tamperedSig, $message);
            if ($valid3) {
                throw new RuntimeException('Should not verify with tampered signature');
            }
        }
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected for edge cases
    }

    try {
        $pk = new PublicKey(substr($input, 0, 32));
        $message = 'test message';
        $signature = substr($input, 32, min(64, strlen($input) - 32));
        $pk->verify($signature, $message);
        // Should almost always be false
    } catch (CryptoException|NotImplementedException|SodiumException|TypeError) {
        // Expected
    }

    try {
        SecretKey::importPem($input, 'rsa');
        throw new RuntimeException('Should reject unsupported algorithm');
    } catch (CryptoException) {
        // Expected
    }

    try {
        PublicKey::importPem($input, 'rsa');
        throw new RuntimeException('Should reject unsupported algorithm');
    } catch (CryptoException) {
        // Expected
    }

    try {
        if (strlen($input) >= 34) {
            $testData = substr($input, 0, 34);
            PublicKey::fromMultibase($testData);
        }
    } catch (CryptoException|EncodingException|TypeError) {
    }
});
