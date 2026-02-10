<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

/**
 * Large-tree tests for IncrementalTree to kill escaped mutants
 * in addLeaf() loop logic, getRootForSubtree(), and
 * getConsistencyProof() boundary conditions.
 */
#[CoversClass(IncrementalTree::class)]
class IncrementalTreeLargeTest extends TestCase
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
     * Property: IncrementalTree root always matches Tree root for trees with 16-64 leaves built incrementally.
     *
     * Kills mutants #4-#13: loop bound, sibling index, left/right ordering, level increment, and integer cast
     * mutations.
     *
     * @throws CryptoException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testLargeTreeRootMatchesBaseTree(
        string $hashAlg
    ): void {
        foreach ([16, 17, 31, 32, 33, 48, 63, 64] as $size) {
            $leaves = array_map(
                fn($i) => "leaf-$i-" . bin2hex(random_bytes(4)),
                range(0, $size - 1)
            );

            $incTree = new IncrementalTree([], $hashAlg);
            foreach ($leaves as $leaf) {
                $incTree->addLeaf($leaf);
            }

            $baseTree = new Tree($leaves, $hashAlg);

            $this->assertEquals(
                $baseTree->getRoot(),
                $incTree->getRoot(),
                "Root mismatch for size=$size, algo=$hashAlg"
            );
            $this->assertSame(
                $baseTree->getSize(),
                $incTree->getSize(),
                "Size mismatch for size=$size"
            );
        }
    }

    /**
     * Property: Inclusion proofs from IncrementalTree verify against base Tree for large trees.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testLargeTreeInclusionProofsCrossVerify(
        string $hashAlg
    ): void {
        $leaves = array_map(
            fn($i) => "cross-verify-$i",
            range(0, 31)
        );

        $incTree = new IncrementalTree([], $hashAlg);
        foreach ($leaves as $leaf) {
            $incTree->addLeaf($leaf);
        }
        $baseTree = new Tree($leaves, $hashAlg);
        $root = $baseTree->getRoot();
        $this->assertNotNull($root);

        // Verify every leaf's inclusion proof from IncrementalTree
        // works with the base Tree's verifier
        foreach ($leaves as $leaf) {
            $incProof = $incTree->getInclusionProof($leaf);
            $this->assertTrue(
                $baseTree->verifyInclusionProof(
                    $root,
                    $leaf,
                    $incProof
                ),
                "IncrementalTree proof failed for '$leaf'"
            );
        }
    }

    /**
     * Property: Consistency proofs from IncrementalTree verify against base Tree for large trees.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testLargeTreeConsistencyProofsCrossVerify(
        string $hashAlg
    ): void {
        $allLeaves = array_map(
            fn($i) => "consistency-$i",
            range(0, 31)
        );

        $fullInc = new IncrementalTree($allLeaves, $hashAlg);
        $fullBase = new Tree($allLeaves, $hashAlg);
        $fullRoot = $fullBase->getRoot();
        $this->assertNotNull($fullRoot);

        foreach ([1, 2, 3, 4, 7, 8, 15, 16, 17, 24, 31] as $old) {
            $oldLeaves = array_slice($allLeaves, 0, $old);
            $oldBase = new Tree($oldLeaves, $hashAlg);
            $oldRoot = $oldBase->getRoot();
            $this->assertNotNull($oldRoot);

            $proof = $fullInc->getConsistencyProof($old);
            $this->assertTrue(
                $fullBase->verifyConsistencyProof(
                    $old,
                    32,
                    $oldRoot,
                    $fullRoot,
                    $proof
                ),
                "Consistency proof failed for oldSize=$old"
            );
        }
    }

    /**
     * Node ordering invariant: leftHash is always the even-indexed child. Verified by ensuring incremental and batch
     * construction produce identical roots at every intermediate step for larger trees.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testNodeOrderingInvariant(
        string $hashAlg
    ): void {
        $incTree = new IncrementalTree([], $hashAlg);

        for ($i = 0; $i < 32; ++$i) {
            $incTree->addLeaf("ordering-$i");

            $leaves = array_map(
                fn($j) => "ordering-$j",
                range(0, $i)
            );
            $baseTree = new Tree($leaves, $hashAlg);

            $this->assertEquals(
                $baseTree->getRoot(),
                $incTree->getRoot(),
                "Ordering invariant violated at size=" . ($i + 1)
            );
        }
    }

    /**
     * getRootForSubtree with leafCount = 0 should NOT be treated
     * as power-of-two. Kills mutant #14.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testEmptySubtreeNotPowerOfTwo(
        string $hashAlg
    ): void {
        $tree = new IncrementalTree(['a', 'b'], $hashAlg);
        $baseTree = new Tree(['a', 'b'], $hashAlg);
        $this->assertEquals($baseTree->getRoot(), $tree->getRoot());
    }

    /**
     * Tests trees with non-aligned power-of-two ranges.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testNonAlignedPowerOfTwoRanges(
        string $hashAlg
    ): void {
        // 12 leaves: getRootForSubtree will be called with
        // various subtree ranges including non-aligned ones
        $leaves = array_map(
            fn($i) => "non-aligned-$i",
            range(0, 11)
        );

        $incTree = new IncrementalTree([], $hashAlg);
        foreach ($leaves as $leaf) {
            $incTree->addLeaf($leaf);
        }
        $baseTree = new Tree($leaves, $hashAlg);

        $this->assertEquals(
            $baseTree->getRoot(),
            $incTree->getRoot()
        );

        // Also test 20 leaves to exercise more subtree patterns
        for ($i = 12; $i < 20; ++$i) {
            $leaf = "non-aligned-$i";
            $leaves[] = $leaf;
            $incTree->addLeaf($leaf);
        }
        $baseTree2 = new Tree($leaves, $hashAlg);
        $this->assertEquals(
            $baseTree2->getRoot(),
            $incTree->getRoot()
        );
    }

    /**
     * Consistency proof boundary: oldSize == newSize should return empty proof.
     *
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProofSameSizeVerification(
        string $hashAlg
    ): void {
        $leaves = array_map(
            fn($i) => "same-size-$i",
            range(0, 15)
        );
        $tree = new IncrementalTree($leaves, $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = $tree->getConsistencyProof(16);
        $this->assertEmpty($proof->proof);

        // Verify same-root proof via verifyConsistencyProof
        $this->assertTrue(
            $tree->verifyConsistencyProof(
                16,
                16,
                $root,
                $root,
                $proof
            )
        );
    }

    /**
     * Consistency proof with oldSize > newSize should return empty proof.
     *
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProofOldSizeExceedsNewSize(
        string $hashAlg
    ): void {
        $tree = new IncrementalTree(
            ['a', 'b', 'c', 'd'],
            $hashAlg
        );
        $proof = $tree->getConsistencyProof(10);
        $this->assertEmpty($proof->proof);
    }

    /**
     * Exercises deep multi-level parent hash propagation by building a tree that fills power-of-two boundaries exactly,
     * then adding one more leaf.
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testDeepParentHashPropagation(
        string $hashAlg
    ): void {
        // Build tree to exactly 16 leaves (4 levels deep)
        $incTree = new IncrementalTree([], $hashAlg);
        $leaves = [];
        for ($i = 0; $i < 16; ++$i) {
            $leaves[] = "deep-$i";
            $incTree->addLeaf("deep-$i");
        }

        $baseTree16 = new Tree($leaves, $hashAlg);
        $this->assertEquals(
            $baseTree16->getRoot(),
            $incTree->getRoot()
        );

        // Adding leaf 17 should propagate all the way up since all previous levels are full
        $leaves[] = "deep-16";
        $incTree->addLeaf("deep-16");
        $baseTree17 = new Tree($leaves, $hashAlg);
        $this->assertEquals(
            $baseTree17->getRoot(),
            $incTree->getRoot()
        );
    }
}
