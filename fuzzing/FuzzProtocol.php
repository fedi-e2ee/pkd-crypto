<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\Exceptions\BundleException;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Exceptions\ParserException;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\Parser;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use PhpFuzzer\Config;
use SodiumException;
use TypeError;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    // Test Bundle::fromJson with arbitrary input
    try {
        $bundle = Bundle::fromJson($input);

        // If parsing succeeded, test accessors
        assert(is_string($bundle->getAction()));
        assert(is_array($bundle->getMessage()));
        assert(is_string($bundle->getRecentMerkleRoot()));
        assert(is_string($bundle->getSignature()));

        // Test round-trip
        $json = $bundle->toJson();
        $bundle2 = Bundle::fromJson($json);
        assert($bundle->getAction() === $bundle2->getAction());
    } catch (TypeError|BundleException|\Exception) {
        // Expected for malformed data
    }

    // Test Parser::fromJson
    try {
        $bundle = Parser::fromJson($input);
        assert(is_string($bundle->getAction()));
    } catch (TypeError|BundleException) {
        // Expected for malformed data
    }

    // Test Parser with structured JSON
    try {
        $decoded = json_decode($input, true);
        if (is_array($decoded) && isset($decoded['action'])) {
            $parser = new Parser();
            $bundle = Bundle::fromJson($input);

            // Test message type detection
            if (in_array($bundle->getAction(), Parser::UNENCRYPTED_ACTIONS, true)) {
                $message = $parser->getUnencryptedMessage($bundle);
                assert(is_string($message->getAction()));
            } else {
                $message = $parser->getEncryptedMessage($bundle);
                assert(is_string($message->getAction()));
            }
        }
    } catch (TypeError|BundleException|CryptoException|ParserException|\Exception) {
        // Expected for malformed data
    }

    // Test parseForActivityPub (should reject BurnDown)
    try {
        $parser = new Parser();
        $parser->parseUnverifiedForActivityPub($input);
    } catch (TypeError|BundleException|CryptoException|NotImplementedException|ParserException|SodiumException) {
        // Expected - most inputs will fail
    }

    // Test with well-formed JSON structure but invalid values
    try {
        $actions = [
            'AddKey',
            'RevokeKey',
            'AddAuxData',
            'RevokeAuxData',
            'BurnDown',
            'Checkpoint',
            'Fireproof',
            'UndoFireproof',
            'MoveIdentity',
            'RevokeKeyThirdParty',
        ];

        $parts = str_split($input, max(1, (int)(strlen($input) / 5)));
        $actionIndex = ord($input[0] ?? "\x00") % count($actions);

        $testJson = json_encode([
            '!pkd-context' => 'https://github.com/fedi-e2ee/public-key-directory/v1',
            'action' => $actions[$actionIndex],
            'message' => [
                'actor' => $parts[0] ?? '',
                'public-key' => $parts[1] ?? '',
                'time' => date('c'),
            ],
            'recent-merkle-root' => base64_encode($parts[2] ?? ''),
            'signature' => base64_encode($parts[3] ?? str_repeat("\x00", 64)),
            'symmetric-keys' => [],
        ]);

        if ($testJson !== false) {
            $bundle = Bundle::fromJson($testJson);
            $parser = new Parser();

            if (in_array($bundle->getAction(), Parser::UNENCRYPTED_ACTIONS, true)) {
                $parser->getUnencryptedMessage($bundle);
            }
        }
    } catch (TypeError|BundleException|CryptoException|ParserException|\Exception) {
        // Expected for edge cases
    }
});
