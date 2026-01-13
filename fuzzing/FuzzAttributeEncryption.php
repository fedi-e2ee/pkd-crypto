<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\SymmetricKey;
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

    // Split input into components
    $keyBytes = substr($input, 0, 32);
    $remaining = substr($input, 32);

    if (strlen($remaining) < 2) {
        return;
    }

    // Use first byte to determine attribute name length
    $attrLen = max(1, ord($remaining[0]) % 64);
    $attrName = substr($remaining, 1, $attrLen);
    $plaintext = substr($remaining, 1 + $attrLen);

    if (empty($attrName) || $plaintext === '') {
        return;
    }

    $v1 = new Version1();
    $key = new SymmetricKey($keyBytes);
    $merkleRoot = hash('sha512', 'test-merkle-root', true);

    // Test encrypt/decrypt round-trip
    try {
        $ciphertext = $v1->encryptAttribute($attrName, $plaintext, $key, $merkleRoot);
        $decrypted = $v1->decryptAttribute($attrName, $ciphertext, $key, $merkleRoot);

        if ($plaintext !== $decrypted) {
            throw new RuntimeException('Encrypt/decrypt round-trip mismatch');
        }
    } catch (TypeError|SodiumException|CryptoException) {
        // Expected for edge cases
    }

    // Test decryption with tampered ciphertext
    try {
        $ciphertext = $v1->encryptAttribute($attrName, $plaintext, $key, $merkleRoot);

        // Tamper with various parts of the ciphertext
        if (strlen($ciphertext) > 97) {
            // Tamper with version byte
            $tampered1 = "\x00" . substr($ciphertext, 1);
            try {
                $v1->decryptAttribute($attrName, $tampered1, $key, $merkleRoot);
                throw new RuntimeException('Should reject invalid version');
            } catch (CryptoException) {
                // Expected
            }

            // Tamper with auth tag
            $tampered2 = substr($ciphertext, 0, 65) .
                str_repeat("\x00", 32) .
                substr($ciphertext, 97);
            try {
                $v1->decryptAttribute($attrName, $tampered2, $key, $merkleRoot);
                throw new RuntimeException('Should reject invalid auth tag');
            } catch (CryptoException) {
                // Expected
            }

            // Tamper with ciphertext portion
            $tampered3 = substr($ciphertext, 0, 97) .
                str_repeat("\xff", strlen($ciphertext) - 97);
            try {
                $v1->decryptAttribute($attrName, $tampered3, $key, $merkleRoot);
                // May or may not fail depending on the tampering
            } catch (CryptoException) {
                // Expected - either auth tag or commitment will fail
            }
        }
    } catch (TypeError|SodiumException|CryptoException) {
        // Expected for edge cases
    }

    // Test decryption with wrong key
    try {
        $ciphertext = $v1->encryptAttribute($attrName, $plaintext, $key, $merkleRoot);
        $wrongKey = new SymmetricKey(str_repeat("\x00", 32));

        try {
            $v1->decryptAttribute($attrName, $ciphertext, $wrongKey, $merkleRoot);
            throw new RuntimeException('Should reject wrong key');
        } catch (CryptoException) {
            // Expected
        }
    } catch (TypeError|SodiumException|CryptoException) {
        // Expected for edge cases
    }

    // Test decryption with wrong attribute name
    try {
        $ciphertext = $v1->encryptAttribute($attrName, $plaintext, $key, $merkleRoot);

        try {
            $v1->decryptAttribute('wrong-attribute', $ciphertext, $key, $merkleRoot);
            throw new RuntimeException('Should reject wrong attribute name');
        } catch (CryptoException) {
            // Expected
        }
    } catch (TypeError|SodiumException|CryptoException) {
        // Expected for edge cases
    }

    // Test with arbitrary ciphertext (should fail gracefully)
    try {
        $v1->decryptAttribute($attrName, $input, $key, $merkleRoot);
    } catch (CryptoException) {
        // Expected - random data should not decrypt
    } catch (TypeError|SodiumException) {
        // Also acceptable
    }
});
