<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Merkle\ConsistencyProof;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(IncrementalTree::class)]
class IncrementalTreeTest extends TestCase
{
    public static function hashAlgProvider(): array
    {
        return [
            ['blake2b'],
            ['sha256'],
            ['sha384'],
            ['sha512'],
        ];
    }

    /**
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testIncrementalFromZero(string $hashAlg): void
    {
        $empty = (new Tree([], $hashAlg))->getEncodedRoot();
        $dummy = random_bytes(32);

        // Let's see if adding more leaves coaxes the two into a compatible state:
        $pieces = [$dummy];
        for ($i = 1; $i < 16; ++$i) {
            $pieces []= random_bytes(32);
            $treeA = new IncrementalTree([], $hashAlg);
            foreach ($pieces as $p) {
                $treeA->addLeaf($p);
            }
            $treeB = new Tree($pieces, $hashAlg);
            $this->assertSame($treeB->getEncodedRoot(), $treeA->getEncodedRoot(), 'extra leaves = ' . $i);
        }

        // Original test:
        $tree = new IncrementalTree([], $hashAlg);
        $this->assertSame($empty, $tree->getEncodedRoot());
        $tree->addLeaf($dummy);
        $this->assertNotSame($empty, $tree->getEncodedRoot());

        $non = new Tree([$dummy], $hashAlg);
        $this->assertSame($non->getEncodedRoot(), $tree->getEncodedRoot());

    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testCompatibilityWithBaseTree(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e'];

        $baseTree = new Tree($leaves, $hashAlg);
        $incrementalTree = new IncrementalTree($leaves, $hashAlg);

        $this->assertEquals($baseTree->getRoot(), $incrementalTree->getRoot());
        $this->assertEquals($baseTree->getSize(), $incrementalTree->getSize());

        $baseProof = $baseTree->getInclusionProof('c');

        // Ensure JSON encoding/decoding works
        $toJson = json_encode($baseProof);
        $this->assertIsString($toJson);
        $fromJson = InclusionProof::fromString($toJson);
        $this->assertSame($fromJson->index, $baseProof->index);
        $this->assertSame($fromJson->proof, $baseProof->proof);

        // Handle consistency proofs
        $proof1 = $baseTree->getConsistencyProof(3);
        $conJson = json_encode($proof1);
        $this->assertIsString($conJson);
        $proof2 = ConsistencyProof::fromString($conJson);
        $this->assertSame($proof1->proof, $proof2->proof);

        $incrementalProof = $incrementalTree->getInclusionProof('c');

        $this->assertTrue(
            $baseTree->verifyInclusionProof($baseTree->getRoot(), 'c', $incrementalProof)
        );
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testEvenLeaves(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd'];

        $baseTree = new Tree($leaves, $hashAlg);
        $incrementalTree = new IncrementalTree($leaves, $hashAlg);

        $this->assertEquals($baseTree->getRoot(), $incrementalTree->getRoot());
        $this->assertEquals($baseTree->getSize(), $incrementalTree->getSize());

        $baseProof = $baseTree->getInclusionProof('b');
        $incrementalProof = $incrementalTree->getInclusionProof('b');

        $this->assertEquals($baseProof, $incrementalProof);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testIncrementalUpdates(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e'];
        $baseTree = new Tree($leaves, $hashAlg);

        $incrementalTree = new IncrementalTree([], $hashAlg);
        foreach ($leaves as $leaf) {
            $incrementalTree->addLeaf($leaf);
        }

        $this->assertEquals($baseTree->getRoot(), $incrementalTree->getRoot());
        $this->assertEquals(count($leaves), $incrementalTree->getSize());
    }

    /**
     * @throws InputException
     * @throws JsonException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testJsonSerialization(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e'];
        $incrementalTree = new IncrementalTree($leaves, $hashAlg);
        $originalRoot = $incrementalTree->getRoot();

        $json = $incrementalTree->toJson();
        $deserializedTree = IncrementalTree::fromJson($json);

        $this->assertEquals($originalRoot, $deserializedTree->getRoot());
        $this->assertEquals($incrementalTree->getSize(), $deserializedTree->getSize());

        // Verify that we can still add leaves and get the correct root.
        $baseTree = new Tree($leaves, $hashAlg);
        $baseTree->addLeaf('f');

        $deserializedTree->addLeaf('f');
        $this->assertEquals($baseTree->getRoot(), $deserializedTree->getRoot());
    }

    /**
     * @throws InputException
     * @throws JsonException
     * @throws SodiumException
     */
    public function testFromJsonInvalidType(): void
    {
        $this->expectException(JsonException::class);
        IncrementalTree::fromJson('123');
    }

    public static function fromJsonMissingProvider(): array
    {
        return [
            ['{"size":0,"nodes":[]}'],
            ['{"hashAlgo":"sha256","nodes":[]}'],
            ['{"hashAlgo":"sha256","size":0}'],
        ];
    }

    /**
     * @throws InputException
     * @throws JsonException
     * @throws SodiumException
     */
    #[DataProvider("fromJsonMissingProvider")]
    public function testFromJsonMissingElements(string $input): void
    {
        $this->expectException(InputException::class);
        IncrementalTree::fromJson($input);
    }

    public static function invalidJsonProvider(): array
    {
        return [
            ["'''", JsonException::class],
            ['0', JsonException::class],
            ['"test"', JsonException::class],
            ['null', JsonException::class],
            ['[]', InputException::class],
            ['{"size":0,"nodes":{}}', InputException::class],
            ['{"hashAlgo":"sha256","nodes":{}}', InputException::class],
            ['{"hashAlgo":"sha256","size":0}', InputException::class],
            ['{"hashAlgo":123,"size":0,"nodes":{}}', InputException::class],
            ['{"hashAlgo":"sha256","size":"0","nodes":{}}', InputException::class],
            ['{"hashAlgo":"sha256","size":0,"nodes":"{}"}', InputException::class],
        ];
    }

    /**
     * @throws InputException
     * @throws JsonException
     * @throws SodiumException
     */
    #[DataProvider("invalidJsonProvider")]
    public function testFromJsonInvalidInput(string $json, string $exceptionClass): void
    {
        $this->expectException($exceptionClass);
        IncrementalTree::fromJson($json);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testEmptyIncrementalTree(string $hashAlg): void
    {
        $tree = new IncrementalTree([], $hashAlg);
        $this->assertNull($tree->getRoot());
        $this->assertSame(0, $tree->getSize());

        // Encoded root should match empty Tree
        $baseTree = new Tree([], $hashAlg);
        $this->assertSame($baseTree->getEncodedRoot(), $tree->getEncodedRoot());
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testSingleLeafIncrementalTree(string $hashAlg): void
    {
        $tree = new IncrementalTree(['a'], $hashAlg);
        $this->assertNotNull($tree->getRoot());
        $this->assertSame(1, $tree->getSize());

        $baseTree = new Tree(['a'], $hashAlg);
        $this->assertEquals($baseTree->getRoot(), $tree->getRoot());
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testGetInclusionProofMissingLeaf(string $hashAlg): void
    {
        $tree = new IncrementalTree(['a', 'b', 'c'], $hashAlg);
        $this->expectException(CryptoException::class);
        $tree->getInclusionProof('missing');
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testGetConsistencyProofInvalidSizes(string $hashAlg): void
    {
        $tree = new IncrementalTree(['a', 'b', 'c'], $hashAlg);

        // oldSize > newSize
        $proof = $tree->getConsistencyProof(10);
        $this->assertEmpty($proof->proof);

        // oldSize == 0
        $proof2 = $tree->getConsistencyProof(0);
        $this->assertEmpty($proof2->proof);

        // oldSize < 0
        $proof3 = $tree->getConsistencyProof(-1);
        $this->assertEmpty($proof3->proof);

        // oldSize == newSize
        $proof4 = $tree->getConsistencyProof(3);
        $this->assertEmpty($proof4->proof);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testPowerOfTwoAlignedSubtrees(string $hashAlg): void
    {
        // Build tree with exactly power-of-two leaves to exercise caching
        $leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
        $tree = new IncrementalTree($leaves, $hashAlg);
        $baseTree = new Tree($leaves, $hashAlg);

        $this->assertEquals($baseTree->getRoot(), $tree->getRoot());
        $this->assertEquals(8, $tree->getSize());

        // Add one more to break power-of-two
        $tree->addLeaf('i');
        $baseTree->addLeaf('i');
        $this->assertEquals($baseTree->getRoot(), $tree->getRoot());
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testAddLeafSiblingPaths(string $hashAlg): void
    {
        $tree = new IncrementalTree([], $hashAlg);

        // Add leaves one by one to test odd/even sibling paths
        for ($i = 1; $i <= 10; ++$i) {
            $tree->addLeaf("leaf$i");
            $baseTree = new Tree(array_map(fn($j) => "leaf$j", range(1, $i)), $hashAlg);
            $this->assertEquals(
                $baseTree->getRoot(),
                $tree->getRoot(),
                "Mismatch after adding leaf $i"
            );
        }
    }

    /**
     * @throws CryptoException
     * @throws InputException
     * @throws JsonException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testJsonRoundTripPreservesState(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e'];
        $tree = new IncrementalTree($leaves, $hashAlg);

        $json = $tree->toJson();
        $restored = IncrementalTree::fromJson($json);

        // Verify basic properties
        $this->assertEquals($tree->getRoot(), $restored->getRoot());
        $this->assertEquals($tree->getSize(), $restored->getSize());

        // Verify inclusion proofs work
        $proof = $tree->getInclusionProof('c');
        $restoredProof = $restored->getInclusionProof('c');
        $this->assertEquals($proof->index, $restoredProof->index);
        $this->assertEquals($proof->proof, $restoredProof->proof);

        // Verify adding more leaves produces same result
        $tree->addLeaf('f');
        $restored->addLeaf('f');
        $this->assertEquals($tree->getRoot(), $restored->getRoot());
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofVariousPositions(string $hashAlg): void
    {
        $leaves = array_map(fn($i) => "leaf$i", range(0, 15));
        $tree = new IncrementalTree($leaves, $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        // Test all positions
        foreach ($leaves as $leaf) {
            $proof = $tree->getInclusionProof($leaf);
            $this->assertTrue(
                $tree->verifyInclusionProof($root, $leaf, $proof),
                "Failed for $leaf"
            );
        }
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProofVerification(string $hashAlg): void
    {
        $allLeaves = array_map(fn($i) => "leaf$i", range(0, 15));
        $fullTree = new IncrementalTree($allLeaves, $hashAlg);
        $fullRoot = $fullTree->getRoot();
        $this->assertNotNull($fullRoot);

        // Test consistency from various old sizes
        foreach ([1, 2, 3, 4, 5, 7, 8, 9, 15] as $oldSize) {
            $oldLeaves = array_slice($allLeaves, 0, $oldSize);
            $oldTree = new IncrementalTree($oldLeaves, $hashAlg);
            $oldRoot = $oldTree->getRoot();
            $this->assertNotNull($oldRoot);

            $proof = $fullTree->getConsistencyProof($oldSize);
            $this->assertTrue(
                $fullTree->verifyConsistencyProof($oldSize, 16, $oldRoot, $fullRoot, $proof),
                "Failed for oldSize=$oldSize"
            );
        }
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testUpdateRootCalled(string $hashAlg): void
    {
        $tree = new IncrementalTree(['a'], $hashAlg);
        $root1 = $tree->getRoot();

        $tree->addLeaf('b');
        $root2 = $tree->getRoot();

        $this->assertNotEquals($root1, $root2);

        // Verify against base tree
        $baseTree = new Tree(['a', 'b'], $hashAlg);
        $this->assertEquals($baseTree->getRoot(), $root2);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testNonPowerOfTwoSubtrees(string $hashAlg): void
    {
        // Test with 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15 leaves
        foreach ([3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15] as $count) {
            $leaves = array_map(fn($i) => "leaf$i", range(0, $count - 1));
            $tree = new IncrementalTree($leaves, $hashAlg);
            $baseTree = new Tree($leaves, $hashAlg);
            $this->assertEquals(
                $baseTree->getRoot(),
                $tree->getRoot(),
                "Mismatch for count=$count"
            );
        }
    }

    /**
     * @throws InputException
     * @throws JsonException
     * @throws SodiumException
     */
    public function testFromJsonInvalidBase64(): void
    {
        $this->expectException(\Exception::class);
        IncrementalTree::fromJson('{"hashAlgo":"sha256","size":1,"nodes":{"0-0":"not-valid-base64!!!"}}');
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testAddLeafSiblingPathsDetailed(string $hashAlg): void
    {
        // Test that the break statement in addLeaf works correctly
        // by verifying the tree state after adding leaves one by one
        $tree = new IncrementalTree([], $hashAlg);
        $roots = [];

        // Build up incrementally and capture each root
        for ($i = 1; $i <= 8; ++$i) {
            $tree->addLeaf("leaf$i");
            $roots[$i] = $tree->getRoot();
            $this->assertNotNull($roots[$i]);

            // Verify against fresh tree
            $freshTree = new Tree(array_map(fn($j) => "leaf$j", range(1, $i)), $hashAlg);
            $this->assertEquals(
                $freshTree->getRoot(),
                $roots[$i],
                "Root mismatch at size $i"
            );
        }

        // Verify all roots are different (proves tree is being updated correctly)
        $uniqueRoots = array_unique($roots, SORT_STRING);
        $this->assertCount(8, $uniqueRoots, "All 8 roots should be unique");
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testSiblingIndexCalculation(string $hashAlg): void
    {
        $tree = new IncrementalTree([], $hashAlg);

        // Add leaf 0 (even index) - sibling would be 1 (doesn't exist)
        $tree->addLeaf('leaf0');
        $root0 = $tree->getRoot();
        $this->assertNotNull($root0);

        // Add leaf 1 (odd index) - sibling is 0 (exists)
        $tree->addLeaf('leaf1');
        $root1 = $tree->getRoot();
        $this->assertNotNull($root1);

        // Root should have changed since sibling exists and parent was calculated
        $this->assertNotEquals($root0, $root1);

        // Verify structure
        $baseTree = new Tree(['leaf0', 'leaf1'], $hashAlg);
        $this->assertEquals($baseTree->getRoot(), $root1);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofMidCalculation(string $hashAlg): void
    {
        // Test with trees of sizes that exercise the mid = start + k calculation
        $leaves = array_map(fn($i) => "leaf$i", range(0, 6));
        $tree = new IncrementalTree($leaves, $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        // Verify proofs for leaf at different positions relative to split point
        // For 7 leaves, k=4, so mid=4, testing index 3 (left subtree) and 4 (right subtree)
        $proof3 = $tree->getInclusionProof('leaf3');
        $this->assertTrue($tree->verifyInclusionProof($root, 'leaf3', $proof3));

        $proof4 = $tree->getInclusionProof('leaf4');
        $this->assertTrue($tree->verifyInclusionProof($root, 'leaf4', $proof4));

        // Also test boundary: exactly at mid
        $proof2 = $tree->getInclusionProof('leaf2');
        $this->assertTrue($tree->verifyInclusionProof($root, 'leaf2', $proof2));
    }
}
