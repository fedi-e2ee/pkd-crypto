<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Merkle\ConsistencyProof;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\Merkle\Tree;
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

    #[DataProvider("fromJsonMissingProvider")]
    public function testFromJsonMissingElements(string $input): void
    {
        $this->expectException(InputException::class);
        IncrementalTree::fromJson($input);
    }
}
