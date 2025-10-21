<?php
declare(strict_types=1);
namespace FediE2EE\PKDServer\Tests\Crypto\Merkle;

use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * @covers Tree
 */
#[CoversClass(Tree::class)]
class TreeTest extends TestCase
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
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofWithEvenLeaves(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd'];
        $tree = new Tree($leaves, $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = $tree->getInclusionProof('c');
        $this->assertNotNull($proof);

        $this->assertTrue(
            $tree->verifyInclusionProof($root, 'c', $proof['proof'], $proof['index'])
        );
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofWithOddLeaves(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd', 'e'];
        $tree = new Tree($leaves, $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = $tree->getInclusionProof('e');
        $this->assertNotNull($proof);
        $this->assertTrue(
            $tree->verifyInclusionProof($root, 'e', $proof['proof'], $proof['index'])
        );

        $proof = $tree->getInclusionProof('d');
        $this->assertNotNull($proof);
        $this->assertTrue(
            $tree->verifyInclusionProof($root, 'd', $proof['proof'], $proof['index'])
        );
    }

    /**
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProof(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c'];
        $tree1 = new Tree($leaves, $hashAlg);
        $root1 = $tree1->getRoot();
        $this->assertNotNull($root1);

        $allLeaves = ['a', 'b', 'c', 'd', 'e'];
        $tree2 = new Tree($allLeaves, $hashAlg);
        $root2 = $tree2->getRoot();

        $proof = $tree2->getConsistencyProof(3);
        $this->assertTrue(
            $tree1->verifyConsistencyProof(3, 5, $root1, $root2, $proof)
        );
    }

    /**
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProofForEmptySubtree(string $hashAlg): void
    {
        $leaves = ['a'];
        $tree1 = new Tree($leaves, $hashAlg);
        $root1 = $tree1->getRoot();

        $allLeaves = ['a', 'b', 'c'];
        $tree2 = new Tree($allLeaves, $hashAlg);
        $root2 = $tree2->getRoot();

        $proof = $tree2->getConsistencyProof(0);
        $this->assertTrue(
            $tree1->verifyConsistencyProof(0, 3, $root1, $root2, $proof)
        );
    }
}
