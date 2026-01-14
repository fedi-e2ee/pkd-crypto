<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Merkle\ConsistencyProof;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\Tree;
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
    public static function insecureHashAlgProvider(): array
    {
        return [
            ['adler32'],
            ['crc32'],
            ['nonsense-hash-func'],
            ['md2'],
            ['md4'],
            ['md5'],
            ['sha1'],
            ['sha224'],
        ];
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testEmpty(string $hashAlg): void
    {
        $tree = new Tree([], $hashAlg);

        $expected = match($hashAlg) {
            'blake2b', 'sha256' =>
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'sha384' =>
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'sha512' =>
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        };
        $this->assertSame(
            $expected,
            $tree->getEncodedRoot(),
        );
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
        $expected = match($hashAlg) {
            'blake2b' => 'pkd-mr-v1:QhNgpgmYA7Rl3_UkbLFkwrb_rFTxfOzAT6e_4lYeGAQ',
            'sha256' => 'pkd-mr-v1:MzdqO9Y-mZNwioTd_mworli4NQXdH-1xG9kk7FpiOfA',
            'sha384' => 'pkd-mr-v1:RbDLKSG-nJN_-x5PqHDQN2J4DVaxwLMrgF0LqCawkV7T6znmy3iDG-TXJ32G4Ccc',
            'sha512' => 'pkd-mr-v1:JiUhMQ_CPQlw_t3zNN__z8gNrO6d4FRjlXq5oJJFH3PKK0jF61eudNBq7px9MDWvWBHaD8nB3zt-5DmklfaErg'
        };
        $this->assertSame(
            $expected,
            $tree->getEncodedRoot(),
        );

        $proof = $tree->getInclusionProof('c');
        $this->assertNotNull($proof);
        $this->assertInstanceOf(InclusionProof::class, $proof);

        $this->assertTrue(
            $tree->verifyInclusionProof($root, 'c', $proof)
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
        $expected = match($hashAlg) {
            'blake2b' => 'pkd-mr-v1:V9NmIuP5ANrdMn-xCLYuKCy49lIl_yR0nfeNCRdsHQ0',
            'sha256' => 'pkd-mr-v1:_hSlQm-9cMD6c_UjQq_tDaC9I8SDhmLM9riKMHDq2Xs',
            'sha384' => 'pkd-mr-v1:NWgj9ZkVvEPSYjVSNgzhQ45j_NQiVmDtmIFNYn15_qp9tH4xwOm_QuqYOEBzykEz',
            'sha512' => 'pkd-mr-v1:iE7_WlEAigFVObBrPIQew_S7Fsj9R1EWXpArLNCWfoH50X-h0e4Llvq-Z8y4wYPYKO1mTGL0A5gN_eHdMdaZfg'
        };
        $this->assertSame(
            $expected,
            $tree->getEncodedRoot(),
        );

        $proof = $tree->getInclusionProof('e');
        $this->assertNotNull($proof);
        $this->assertTrue(
            $tree->verifyInclusionProof($root, 'e', $proof)
        );

        $proof = $tree->getInclusionProof('d');
        $this->assertNotNull($proof);
        $this->assertTrue(
            $tree->verifyInclusionProof($root, 'd', $proof)
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
        $this->assertInstanceOf(ConsistencyProof::class, $proof);
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
        $this->assertInstanceOf(ConsistencyProof::class, $proof);
        $this->assertTrue(
            $tree1->verifyConsistencyProof(0, 3, $root1, $root2, $proof)
        );
    }

    /**
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testEmptyTree(string $hashAlg): void
    {
        $tree = new Tree([], $hashAlg);
        $this->assertNull($tree->getRoot());
        $this->assertSame(0, $tree->getSize());
    }

    /**
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testSingleLeafTree(string $hashAlg): void
    {
        $tree = new Tree(['a'], $hashAlg);
        $this->assertNotNull($tree->getRoot());
        $this->assertSame(1, $tree->getSize());
        $this->assertTrue(
            hash_equals(
                $tree->hashLeaf('a'),
                $tree->getRoot()
            )
        );
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testInclusionProofForMissingLeaf(): void
    {
        $this->expectException(CryptoException::class);
        $tree = new Tree(['a', 'b', 'c']);
        $tree->getInclusionProof('d');
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     * @dataProvider hashAlgProvider
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyInclusionProofFailure(string $hashAlg): void
    {
        $leaves = ['a', 'b', 'c', 'd'];
        $tree = new Tree($leaves, $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = $tree->getInclusionProof('c');
        $this->assertNotNull($proof);

        $this->assertFalse(
            $tree->verifyInclusionProof($root, 'd', $proof)
        );
    }


    #[DataProvider("insecureHashAlgProvider")]
    /**
     * @throws SodiumException
     */
    public function testRejectInsecure(string $hashAlg): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('This hash function is not permitted: ' . $hashAlg);
        new Tree([], $hashAlg);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testKnownAnswerInternal(string $hashAlg): void
    {
        // Start with some leaves
        $tree = new Tree([
            sodium_bin2hex('76b53f0355924d554637fa12f0013594627e961c85898ea4d405921a0692fe66a17c4cf3085994ae8c337770b8f62acb50065e5814f784f37e2234af6d03995f'),
            sodium_bin2hex('f0744c1e6ff6c54283e485b18b595ad183b93f01906f29df36127ff69ef4c9b7'),
            sodium_bin2hex('9ec1764dfdb6d8ff511c94cdf3496d7259f97514701428d52d8d0cf05d260c73'),
            sodium_bin2hex('6a313a049b6fedb0b9e156527ed80cc42d342b2c7bda8c1db87d21c2e561468b'),
        ], $hashAlg);
        $root = $tree->getEncodedRoot();
        $expected1 = match ($hashAlg) {
            'blake2b' => 'pkd-mr-v1:eS9FxLEc9YTNiesIOL1cono1n7u3VuH4WRm9hPGLA9I',
            'sha256' => 'pkd-mr-v1:CH0-7A8ry0FMVD7i7urGHqcTuL4ueMlYmXxE0bzxwCI',
            'sha384' => 'pkd-mr-v1:48tTulgIWNDjKT-aSVmCL8hW1BbXDmLR7UXyuwTWYy4msh-rEf1WlQgeiHmXCv_L',
            'sha512' => 'pkd-mr-v1:czy8MCjUDCzsu0-d7OHRdXf2y58tszxFXfaEZCP4bv1sJK7yCgL1LUKvXdPbwOqatjQqBaYpt8k2WCErsOz1tw',
        };
        $this->assertSame($expected1, $root);

        // Add another leaf
        $newLeaf = sodium_bin2hex('9c1900e20895cc9b92d82d94aa9117432fe930a56d02015dbca7ab0fc49d1834');
        $tree->addLeaf($newLeaf);

        $root = $tree->getEncodedRoot();
        $expected2 = match ($hashAlg) {
            'blake2b' => 'pkd-mr-v1:fUkSRnyXBBWO7dN5c0DF6ez4KNexSArLlotB9x3M_Rk',
            'sha256' => 'pkd-mr-v1:pMuu_3rgLYrVc5Nljatotbo9Mue7qp437Cg_0NAq3h0',
            'sha384' => 'pkd-mr-v1:4IkmMGSWp2mvNLhehZ8IKu9uisaBd5vTdFHPoVzlzzmmbi6MuhvGPr9xm8O2pk-Y',
            'sha512' => 'pkd-mr-v1:IPYsZtgnh2DwBFgSm8vtVVyBf3bv_FrfXpM6xdJU3uYJioo4ZCH8rFyv_EafWJNSX4hZL8IVnPL_VPZ-WttEMg',
        };
        $this->assertSame($expected2, $root);

        // Generate and verify an inclusion proof:
        $inclusion = $tree->getInclusionProof($newLeaf);
        $this->assertTrue($tree->verifyInclusionProof($tree->getRoot(), $newLeaf, $inclusion));
    }

    public static function splitPointProvider(): array
    {
        return [
            [0, 0],
            [1, 0],
            [2, 1],
            [3, 2],
            [4, 2],
            [5, 4],
            [6, 4],
            [7, 4],
            [8, 4],
            [9, 8],
            [16, 8],
            [17, 16],
            [32, 16],
            [33, 32],
            [64, 32],
            [65, 64],
            [128, 64],
            [129, 128],
            [192, 128],
            [256, 128],
        ];
    }

    #[DataProvider("splitPointProvider")]
    public function testGetSplitPoint(int $input, $expected): void
    {
        $this->assertSame($expected, Tree::getSplitPoint($input));
    }

    public function testIsHashFunctionAllowed(): void
    {
        $this->assertFalse(Tree::isHashFunctionAllowed('crc32'));
        $this->assertFalse(Tree::isHashFunctionAllowed('adler32'));
        $this->assertFalse(Tree::isHashFunctionAllowed('md5'));
        $this->assertFalse(Tree::isHashFunctionAllowed('sha1'));
        $this->assertTrue(Tree::isHashFunctionAllowed('blake2b'));
    }
}
