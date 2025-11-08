<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

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

    #[DataProvider("hashAlgProvider")]
    public function testIncrementalFromZero(string $hashAlg): void
    {
        $dummy = random_bytes(32);
        $tree = new IncrementalTree();
        $this->assertSame('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $tree->getEncodedRoot());
        $tree->addLeaf($dummy);
        $tree->getRoot();
        $this->assertNotSame('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $tree->getEncodedRoot());
    }

    #[DataProvider("hashAlgProvider")]
    public function testCompatibilityWithBaseTree(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e'];

        $baseTree = new Tree($leaves, $hashAlg);
        $incrementalTree = new IncrementalTree($leaves, $hashAlg);

        $this->assertEquals($baseTree->getRoot(), $incrementalTree->getRoot());
        $this->assertEquals($baseTree->getSize(), $incrementalTree->getSize());

        $baseProof = $baseTree->getInclusionProof('c');
        $incrementalProof = $incrementalTree->getInclusionProof('c');

        $this->assertEquals($baseProof, $incrementalProof);

        $this->assertTrue(
            $incrementalTree->verifyInclusionProof($incrementalTree->getRoot(), 'c', $baseProof)
        );
    }

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
}
