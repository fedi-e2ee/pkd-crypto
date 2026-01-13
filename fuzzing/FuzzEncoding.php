<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\Encoding\Base58BtcVarTime;
use FediE2EE\PKD\Crypto\Encoding\Multibase;
use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PhpFuzzer\Config;
use RuntimeException;
use TypeError;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    // Test Base58Btc encoding round-trip
    try {
        $encoded = Base58BtcVarTime::encode($input);
        $decoded = Base58BtcVarTime::decode($encoded);

        if ($input !== $decoded) {
            throw new RuntimeException('Base58Btc round-trip mismatch');
        }
    } catch (TypeError|EncodingException) {
        // Expected for certain inputs
    }

    // Test Base58Btc decoding of arbitrary input
    try {
        Base58BtcVarTime::decode($input);
    } catch (TypeError|EncodingException) {
        // Expected for invalid base58 strings
    }

    // Test Multibase encoding round-trip for various bases
    $bases = ['base16', 'base32', 'base58btc', 'base64', 'base64url'];

    foreach ($bases as $base) {
        try {
            $encoded = Multibase::encode($base, $input);
            $result = Multibase::decode($encoded);

            if ($result['data'] !== $input) {
                throw new RuntimeException("Multibase $base round-trip mismatch");
            }
            if ($result['encoding'] !== $base) {
                throw new RuntimeException("Multibase $base encoding identifier mismatch");
            }
        } catch (TypeError|EncodingException) {
            // Expected for certain inputs
        }
    }

    // Test Multibase decoding of arbitrary input
    try {
        Multibase::decode($input);
    } catch (TypeError|EncodingException) {
        // Expected for invalid multibase strings
    }

    // Test Base64UrlSafe round-trip (from paragonie/constant_time_encoding)
    try {
        $encoded = Base64UrlSafe::encodeUnpadded($input);
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);

        if ($input !== $decoded) {
            throw new RuntimeException('Base64UrlSafe round-trip mismatch');
        }
    } catch (TypeError) {
        // Expected for edge cases
    }

    // Test multibase with leading zeros (important edge case)
    try {
        $withZeros = "\x00\x00\x00" . $input;
        $encoded = Multibase::encode('base58btc', $withZeros);
        $result = Multibase::decode($encoded);

        if ($result['data'] !== $withZeros) {
            throw new RuntimeException('Multibase leading zeros mismatch');
        }
    } catch (TypeError|EncodingException) {
        // Expected for certain inputs
    }
});
