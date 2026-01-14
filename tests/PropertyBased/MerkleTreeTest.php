<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Property-based tests for Merkle tree operations.
 *
 * These tests verify RFC 9162 compliance and cryptographic properties.
 */
#[CoversClass(Tree::class)]
class MerkleTreeTest extends TestCase
{
    use TestTrait;
    use ErisPhpUnit12Trait {
        ErisPhpUnit12Trait::getTestCaseAnnotations insteadof TestTrait;
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->erisSetupCompat();
    }

    /**
     * Property: Empty tree has null root (before encoding).
     */
    public function testEmptyTreeRoot(): void
    {
        $tree = new Tree();
        $this->assertNull($tree->getRoot());
        $this->assertSame(0, $tree->getSize());
    }

    /**
     * Property: Tree size equals number of leaves added.
     *
     * |tree| == count(leaves)
     */
    public function testTreeSizeEqualsLeafCount(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $leafCount): void {
            $leaves = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves[] = "leaf-$i-" . bin2hex(random_bytes(8));
            }

            $tree = new Tree($leaves);
            $this->assertSame($leafCount, $tree->getSize());
        });
    }

    /**
     * Property: Adding a leaf increases tree size by 1.
     *
     * |tree'| == |tree| + 1 after addLeaf()
     */
    public function testAddLeafIncrementsSize(): void
    {
        $this->forAll(
            Generators::choose(0, 20),
            Generators::choose(1, 10)
        )->then(function (int $initialCount, int $addCount): void {
            $leaves = [];
            for ($i = 0; $i < $initialCount; $i++) {
                $leaves[] = "initial-$i";
            }

            $tree = new Tree($leaves);
            $this->assertSame($initialCount, $tree->getSize());

            for ($i = 0; $i < $addCount; $i++) {
                $tree->addLeaf("added-$i");
                $this->assertSame($initialCount + $i + 1, $tree->getSize());
            }
        });
    }

    /**
     * Property: Root changes when leaf is added.
     *
     * root(tree') != root(tree) after addLeaf() (for non-empty trees)
     */
    public function testRootChangesOnAddLeaf(): void
    {
        $this->forAll(
            Generators::choose(1, 30)
        )->then(function (int $initialCount): void {
            $leaves = [];
            for ($i = 0; $i < $initialCount; $i++) {
                $leaves[] = "leaf-$i";
            }

            $tree = new Tree($leaves);
            $oldRoot = $tree->getRoot();

            $tree->addLeaf('new-leaf-' . bin2hex(random_bytes(8)));
            $newRoot = $tree->getRoot();

            $this->assertNotSame($oldRoot, $newRoot, 'Root should change when leaf is added');
        });
    }

    /**
     * Property: Same leaves in same order produce same root (determinism).
     *
     * root(tree1) == root(tree2) when leaves are identical
     */
    public function testDeterministicRoot(): void
    {
        $this->forAll(
            Generators::choose(1, 30)
        )->then(function (int $leafCount): void {
            $leaves = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves[] = "leaf-$i";
            }

            $tree1 = new Tree($leaves);
            $tree2 = new Tree($leaves);

            $this->assertSame($tree1->getRoot(), $tree2->getRoot());
            $this->assertSame($tree1->getEncodedRoot(), $tree2->getEncodedRoot());
        });
    }

    /**
     * Property: Different leaves produce different roots.
     *
     * root(tree1) != root(tree2) when leaves differ
     */
    public function testDifferentLeavesDifferentRoots(): void
    {
        $this->forAll(
            Generators::choose(1, 20)
        )->then(function (int $leafCount): void {
            $leaves1 = [];
            $leaves2 = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves1[] = "set1-leaf-$i";
                $leaves2[] = "set2-leaf-$i";
            }

            $tree1 = new Tree($leaves1);
            $tree2 = new Tree($leaves2);

            $this->assertNotSame($tree1->getRoot(), $tree2->getRoot());
        });
    }

    /**
     * Property: Leaf order matters for root.
     *
     * root([a, b]) != root([b, a])
     */
    public function testLeafOrderMatters(): void
    {
        $this->forAll(
            Generators::choose(2, 20)
        )->then(function (int $leafCount): void {
            $leaves = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves[] = "leaf-$i";
            }

            $tree1 = new Tree($leaves);
            $tree2 = new Tree(array_reverse($leaves));

            $this->assertNotSame(
                $tree1->getRoot(),
                $tree2->getRoot(),
                'Leaf order should affect root'
            );
        });
    }

    /**
     * Property: Inclusion proof verifies for any added leaf.
     *
     * verify(getInclusionProof(leaf)) == true
     */
    public function testInclusionProofVerifies(): void
    {
        $this->forAll(
            Generators::choose(1, 30)
        )->then(function (int $leafCount): void {
            $leaves = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves[] = "leaf-$i-" . bin2hex(random_bytes(4));
            }

            $tree = new Tree($leaves);
            $root = $tree->getRoot();

            // Verify inclusion proof for each leaf
            foreach ($leaves as $leaf) {
                $proof = $tree->getInclusionProof($leaf);
                $isValid = $tree->verifyInclusionProof($root, $leaf, $proof);
                $this->assertTrue($isValid, "Inclusion proof should verify for leaf: $leaf");
            }
        });
    }

    /**
     * Property: Inclusion proof fails for non-existent leaf.
     */
    public function testInclusionProofFailsForNonExistentLeaf(): void
    {
        $this->forAll(
            Generators::choose(1, 20)
        )->then(function (int $leafCount): void {
            $leaves = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves[] = "leaf-$i";
            }

            $tree = new Tree($leaves);

            $this->expectException(\FediE2EE\PKD\Crypto\Exceptions\CryptoException::class);
            $tree->getInclusionProof('non-existent-leaf');
        });
    }

    /**
     * Property: Consistency proof verifies between tree sizes.
     *
     * verify(getConsistencyProof(oldSize)) == true
     */
    public function testConsistencyProofVerifies(): void
    {
        $this->forAll(
            Generators::choose(1, 15),
            Generators::choose(1, 15)
        )->then(function (int $oldSize, int $additionalLeaves): void {
            // Build initial tree
            $leaves = [];
            for ($i = 0; $i < $oldSize; $i++) {
                $leaves[] = "leaf-$i";
            }

            $oldTree = new Tree($leaves);
            $oldRoot = $oldTree->getRoot();

            // Add more leaves
            $newTree = new Tree($leaves);
            for ($i = 0; $i < $additionalLeaves; $i++) {
                $newTree->addLeaf("new-leaf-$i");
            }
            $newRoot = $newTree->getRoot();
            $newSize = $newTree->getSize();

            // Get and verify consistency proof
            $proof = $newTree->getConsistencyProof($oldSize);
            $isValid = $newTree->verifyConsistencyProof(
                $oldSize,
                $newSize,
                $oldRoot,
                $newRoot,
                $proof
            );

            $this->assertTrue(
                $isValid,
                "Consistency proof should verify (old=$oldSize, new=$newSize)"
            );
        });
    }

    /**
     * Property: Encoded root has correct prefix.
     */
    public function testEncodedRootPrefix(): void
    {
        $this->forAll(
            Generators::choose(0, 30)
        )->then(function (int $leafCount): void {
            $leaves = [];
            for ($i = 0; $i < $leafCount; $i++) {
                $leaves[] = "leaf-$i";
            }

            $tree = new Tree($leaves);
            $encodedRoot = $tree->getEncodedRoot();

            $this->assertStringStartsWith('pkd-mr-v1:', $encodedRoot);
        });
    }

    /**
     * Property: Tree works with all allowed hash algorithms.
     */
    public function testAllowedHashAlgorithms(): void
    {
        $allowedAlgos = ['sha256', 'sha384', 'sha512', 'blake2b'];

        foreach ($allowedAlgos as $algo) {
            $tree = new Tree(['leaf1', 'leaf2', 'leaf3'], $algo);
            $this->assertSame(3, $tree->getSize());
            $this->assertNotNull($tree->getRoot());
            $this->assertStringStartsWith('pkd-mr-v1:', $tree->getEncodedRoot());
        }

        $this->assertTrue(true);
    }

    /**
     * Property: Disallowed hash algorithms are rejected.
     */
    public function testDisallowedHashAlgorithms(): void
    {
        $disallowed = ['md5', 'sha1', 'crc32'];

        foreach ($disallowed as $algo) {
            try {
                new Tree(['leaf'], $algo);
                $this->fail("Algorithm '$algo' should be rejected");
            } catch (\FediE2EE\PKD\Crypto\Exceptions\CryptoException $e) {
                $this->assertStringContainsString('not permitted', $e->getMessage());
            }
        }
    }

    /**
     * Property: Single leaf tree has inclusion proof.
     */
    public function testSingleLeafInclusionProof(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $leaf = 'single-leaf-' . bin2hex(random_bytes(8));
            $tree = new Tree([$leaf]);

            $proof = $tree->getInclusionProof($leaf);
            $isValid = $tree->verifyInclusionProof($tree->getRoot(), $leaf, $proof);

            $this->assertTrue($isValid);
            $this->assertSame(0, $proof->index);
        });
    }
}
