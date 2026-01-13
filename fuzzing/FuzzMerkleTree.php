<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Fuzzing;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Merkle\ConsistencyProof;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use PhpFuzzer\Config;
use RangeException;
use TypeError;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    // Test InclusionProof construction with fuzzed data
    try {
        $decoded = json_decode($input, true);
        if (is_array($decoded)) {
            $index = $decoded['index'] ?? 0;
            $proof = $decoded['proof'] ?? [];

            if (is_int($index) && is_array($proof)) {
                $inclusionProof = new InclusionProof($index, $proof);
                assert(is_int($inclusionProof->index));
                assert(is_array($inclusionProof->proof));
            }
        }
    } catch (TypeError|CryptoException) {
        // Expected for malformed data
    }

    // Test ConsistencyProof construction
    try {
        $decoded = json_decode($input, true);
        if (is_array($decoded) && isset($decoded['proof']) && is_array($decoded['proof'])) {
            $consistencyProof = new ConsistencyProof($decoded['proof']);
            assert(is_array($consistencyProof->proof));
        }
    } catch (TypeError|CryptoException) {
        // Expected for malformed data
    }

    // Test IncrementalTree::fromJson with valid structure
    // NOTE: fromJson does not validate input - found via fuzzing
    try {
        $decoded = json_decode($input, true);
        if (
            \is_array($decoded) &&
            isset($decoded['hashAlgo'], $decoded['size'], $decoded['nodes']) &&
            \is_string($decoded['hashAlgo']) &&
            \is_int($decoded['size']) &&
            \is_array($decoded['nodes'])
        ) {
            $tree = IncrementalTree::fromJson($input);
            $json = $tree->toJson();
            assert(\is_string($json));
            assert(\is_string($tree->getRoot()));
            assert(\is_string($tree->getEncodedRoot()));
        }
    } catch (TypeError|RangeException|CryptoException|\Exception) {
        // Expected for malformed data
    }

    // Test Tree construction with leaf data
    try {
        $leaves = [];
        if (strlen($input) >= 32) {
            $chunks = str_split($input, 32);
            foreach ($chunks as $chunk) {
                if (strlen($chunk) === 32) {
                    $leaves[] = $chunk;
                }
            }
        }

        if (!empty($leaves)) {
            $tree = new Tree($leaves, 'sha512');
            $root = $tree->getRoot();
            $tree->getEncodedRoot();

            if (count($leaves) > 0) {
                $proof = $tree->getInclusionProof($leaves[0]);
                $valid = $tree->verifyInclusionProof($root, $leaves[0], $proof);
                assert($valid === true);
            }
        }
    } catch (TypeError|CryptoException) {
        // Expected for edge cases
    }

    // Test IncrementalTree operations
    try {
        $tree = new IncrementalTree([], 'sha512');

        $chunks = str_split($input, 32);
        foreach ($chunks as $chunk) {
            if (strlen($chunk) > 0) {
                $tree->addLeaf($chunk);
            }
        }

        $tree->updateRoot();
        $root = $tree->getRoot();

        // Verify proofs for added leaves
        foreach ($chunks as $chunk) {
            if (strlen($chunk) > 0) {
                $proof = $tree->getInclusionProof($chunk);
                $valid = $tree->verifyInclusionProof($root, $chunk, $proof);
                assert($valid === true);
            }
        }
    } catch (TypeError|CryptoException) {
        // Expected for edge cases
    }

    // Test consistency proofs between tree sizes
    try {
        if (strlen($input) >= 64) {
            $chunks = str_split($input, 16);
            $halfPoint = (int) (count($chunks) / 2);

            $oldLeaves = array_slice($chunks, 0, max(1, $halfPoint));
            $newLeaves = $chunks;

            $oldTree = new Tree($oldLeaves, 'sha512');
            $oldRoot = $oldTree->getRoot();
            $oldSize = $oldTree->getSize();

            $newTree = new Tree($newLeaves, 'sha512');
            $newRoot = $newTree->getRoot();
            $newSize = $newTree->getSize();

            if ($oldSize < $newSize && $oldSize > 0) {
                $proof = $newTree->getConsistencyProof($oldSize);
                $valid = $newTree->verifyConsistencyProof(
                    $oldSize,
                    $newSize,
                    $oldRoot,
                    $newRoot,
                    $proof
                );
                assert($valid === true);
            }
        }
    } catch (TypeError|CryptoException) {
        // Expected for edge cases
    }
});
