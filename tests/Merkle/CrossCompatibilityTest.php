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

#[CoversClass(IncrementalTree::class)]
class CrossCompatibilityTest extends TestCase
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
     * @throws CryptoException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testComplexInclusionProof(string $hashAlg): void
    {
        $this->runComplexInclusionProofWithLeaves($hashAlg, 100);
        $this->runComplexInclusionProofWithLeaves($hashAlg, 99);
        $this->runComplexInclusionProofWithLeaves($hashAlg, 129);
        $this->runComplexInclusionProofWithLeaves($hashAlg, 2);
        $this->runComplexInclusionProofWithLeaves($hashAlg, 3);
    }

    /**
     * @throws CryptoException
     * @throws RandomException
     * @throws SodiumException
     */
    private function runComplexInclusionProofWithLeaves(string $hashAlg, int $numLeaves): void
    {
        $leaves = [];
        for ($i = 0; $i < $numLeaves; ++$i) {
            $leaves[] = random_bytes(32);
        }

        $baseTree = new Tree($leaves, $hashAlg);
        $incrementalTree = new IncrementalTree($leaves, $hashAlg);

        $this->assertEquals($baseTree->getRoot(), $incrementalTree->getRoot());

        foreach ($leaves as $leaf) {
            $incrementalProof = $incrementalTree->getInclusionProof($leaf);
            $this->assertTrue(
                $baseTree->verifyInclusionProof($baseTree->getRoot(), $leaf, $incrementalProof),
                'Failed for leaf: ' . bin2hex($leaf) . ' with ' . $numLeaves . ' leaves'
            );
        }
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testComplexConsistencyProof(string $hashAlg): void
    {
        $this->runComplexConsistencyProofWithLeaves($hashAlg, 100, 50);
        $this->runComplexConsistencyProofWithLeaves($hashAlg, 100, 99);
        $this->runComplexConsistencyProofWithLeaves($hashAlg, 129, 100);
        $this->runComplexConsistencyProofWithLeaves($hashAlg, 2, 1);
        $this->runComplexConsistencyProofWithLeaves($hashAlg, 3, 2);
    }

    /**
     * @throws RandomException
     * @throws SodiumException
     */
    private function runComplexConsistencyProofWithLeaves(string $hashAlg, int $newSize, int $oldSize): void
    {
        $leaves = [];
        for ($i = 0; $i < $newSize; ++$i) {
            $leaves[] = random_bytes(32);
        }

        $newBaseTree = new Tree($leaves, $hashAlg);
        $newIncrementalTree = new IncrementalTree($leaves, $hashAlg);

        $oldLeaves = array_slice($leaves, 0, $oldSize);
        $oldBaseTree = new Tree($oldLeaves, $hashAlg);
        $oldIncrementalTree = new IncrementalTree($oldLeaves, $hashAlg);

        $this->assertEquals($newBaseTree->getRoot(), $newIncrementalTree->getRoot());
        $this->assertEquals($oldBaseTree->getRoot(), $oldIncrementalTree->getRoot());

        $incrementalProof = $newIncrementalTree->getConsistencyProof($oldSize);
        $this->assertTrue(
            $newBaseTree->verifyConsistencyProof(
                $oldSize,
                $newSize,
                $oldBaseTree->getRoot(),
                $newBaseTree->getRoot(),
                $incrementalProof
            ),
            'Failed for consistency proof with newSize=' . $newSize . ' and oldSize=' . $oldSize
        );
    }

    public static function hashAlgAndLeavesProvider(): array
    {
        $cases = [];
        foreach (self::hashAlgProvider() as $hashAlg) {
            foreach ([2, 3, 99, 100, 129] as $numLeaves) {
                $cases[] = [$hashAlg[0], $numLeaves];
            }
        }
        return $cases;
    }

    /**
     * @throws SodiumException
     * @throws RandomException
     * @throws CryptoException
     */
    #[DataProvider("hashAlgAndLeavesProvider")]
    public function testWithSerializationAndDeserialization(string $hashAlg, int $numLeaves): void
    {
        $leaves = [];
        $incrementalTree = new IncrementalTree([], $hashAlg);

        for ($i = 0; $i < $numLeaves; ++$i) {
            $leaf = random_bytes(32);
            $leaves[] = $leaf;

            // Add the leaf to the incremental tree
            $incrementalTree->addLeaf($leaf);

            // Serialize and deserialize
            $json = $incrementalTree->toJson();
            $deserializedTree = IncrementalTree::fromJson($json);

            // Create a base tree for verification
            $baseTree = new Tree($leaves, $hashAlg);

            // Assert root equality
            $this->assertEquals(
                $baseTree->getRoot(),
                $deserializedTree->getRoot(),
                "Root mismatch at size {$i}"
            );

            // Verify inclusion proofs for all leaves
            foreach ($leaves as $l) {
                $proof = $deserializedTree->getInclusionProof($l);
                $this->assertTrue(
                    $baseTree->verifyInclusionProof($baseTree->getRoot(), $l, $proof),
                    "Inclusion proof failed for leaf " . bin2hex($l) . " at size {$i}"
                );
            }

            // Verify consistency proofs
            for ($oldSize = 1; $oldSize <= $i; ++$oldSize) {
                $oldLeaves = array_slice($leaves, 0, $oldSize);
                $oldBaseTree = new Tree($oldLeaves, $hashAlg);
                $consistencyProof = $deserializedTree->getConsistencyProof($oldSize);
                $this->assertTrue(
                    $baseTree->verifyConsistencyProof(
                        $oldSize,
                        count($leaves),
                        $oldBaseTree->getRoot(),
                        $baseTree->getRoot(),
                        $consistencyProof
                    ),
                    "Consistency proof failed for oldSize {$oldSize} and newSize " . count($leaves)
                );
            }

            // The original incremental tree should still be fine
            $this->assertEquals(
                $baseTree->getRoot(),
                $incrementalTree->getRoot(),
                "Original incremental tree root mismatch at size {$i}"
            );
        }
    }
}
