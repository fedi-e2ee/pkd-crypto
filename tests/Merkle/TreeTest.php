<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Merkle\ConsistencyProof;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use ParagonIE\ConstantTime\Base64UrlSafe;
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
            ['sha3-256'],
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
            'blake2b', 'sha256', 'sha3-256' =>
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
            'sha3-256' => 'pkd-mr-v1:gSnihg8t_wUXNZVNa-JKpstioGDzZJfQe4EbjabZmrs',
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
            'sha3-256' => 'pkd-mr-v1:BLNFnlMEtSt_TDsZRFf67DTZ_AFo3Pg4880PSpplMh8',
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
            'sha3-256' => 'pkd-mr-v1:cz2IpuVoPZ39rZr7KtO-LWkAFrIGfFslUsZpsFrmHdg',
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
            'sha3-256' => 'pkd-mr-v1:hqqu_geVr9x5I-ES2pElZ0Y3CKAyxIJmPnaXB8OdOrI',
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
        // Test all allowed hash algorithms
        $this->assertTrue(Tree::isHashFunctionAllowed('sha256'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha384'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha512'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha512/224'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha512/256'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha3-256'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha3-384'));
        $this->assertTrue(Tree::isHashFunctionAllowed('sha3-512'));
        // Test unknown/non-existent hash function
        $this->assertFalse(Tree::isHashFunctionAllowed('not-a-real-hash'));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyInclusionProofWithInvalidIndex(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        // Create a proof with an index that exceeds the tree size
        $proof = new InclusionProof(100, []);
        $this->assertFalse($tree->verifyInclusionProof($root, 'a', $proof));

        // Test with index equal to size (should fail)
        $proof2 = new InclusionProof(4, []);
        $this->assertFalse($tree->verifyInclusionProof($root, 'a', $proof2));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyInclusionProofWithEmptyProof(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        // Empty proof should fail for multi-leaf tree
        $proof = new InclusionProof(0, []);
        $this->assertFalse($tree->verifyInclusionProof($root, 'a', $proof));
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyInclusionProofWithTamperedRoot(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = $tree->getInclusionProof('c');

        // Tamper with the root
        $tamperedRoot = str_repeat("\x00", strlen($root));
        $this->assertFalse($tree->verifyInclusionProof($tamperedRoot, 'c', $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofOldSizeGreaterThanNew(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = new ConsistencyProof([]);
        // oldSize > newSize should return false
        $this->assertFalse($tree->verifyConsistencyProof(5, 3, $root, $root, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofNegativeOldSize(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = new ConsistencyProof([]);
        // negative oldSize should return false
        $this->assertFalse($tree->verifyConsistencyProof(-1, 3, $root, $root, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofSameSizeMatchingRoots(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = new ConsistencyProof([]);
        // same size with matching roots and empty proof should return true
        $this->assertTrue($tree->verifyConsistencyProof(3, 3, $root, $root, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofSameSizeDifferentRoots(string $hashAlg): void
    {
        $tree1 = new Tree(['a', 'b', 'c'], $hashAlg);
        $root1 = $tree1->getRoot();
        $this->assertNotNull($root1);

        $tree2 = new Tree(['x', 'y', 'z'], $hashAlg);
        $root2 = $tree2->getRoot();
        $this->assertNotNull($root2);

        $proof = new ConsistencyProof([]);
        // same size with different roots should return false
        $this->assertFalse($tree1->verifyConsistencyProof(3, 3, $root1, $root2, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofZeroOldSize(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        // oldSize == 0 with empty proof should return true
        $proof = new ConsistencyProof([]);
        $this->assertTrue($tree->verifyConsistencyProof(0, 3, null, $root, $proof));

        // oldSize == 0 with non-empty proof should return false
        $proofWithData = new ConsistencyProof(['something']);
        $this->assertFalse($tree->verifyConsistencyProof(0, 3, null, $root, $proofWithData));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofNullOldRoot(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd', 'e'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = $tree->getConsistencyProof(3);
        // null oldRoot with oldSize > 0 should return false
        $this->assertFalse($tree->verifyConsistencyProof(3, 5, null, $root, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofEmptyProofWhenNeeded(string $hashAlg): void
    {
        $tree1 = new Tree(['a', 'b', 'c'], $hashAlg);
        $root1 = $tree1->getRoot();
        $this->assertNotNull($root1);

        $tree2 = new Tree(['a', 'b', 'c', 'd', 'e'], $hashAlg);
        $root2 = $tree2->getRoot();
        $this->assertNotNull($root2);

        // Empty proof when we need one should return false
        $emptyProof = new ConsistencyProof([]);
        $this->assertFalse($tree1->verifyConsistencyProof(3, 5, $root1, $root2, $emptyProof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofPowerOfTwoOldSize(string $hashAlg): void
    {
        // Create trees where oldSize is a power of two (4)
        $tree1 = new Tree(['a', 'b', 'c', 'd'], $hashAlg);
        $root1 = $tree1->getRoot();
        $this->assertNotNull($root1);

        $tree2 = new Tree(['a', 'b', 'c', 'd', 'e', 'f'], $hashAlg);
        $root2 = $tree2->getRoot();
        $this->assertNotNull($root2);

        $proof = $tree2->getConsistencyProof(4);
        $this->assertTrue($tree2->verifyConsistencyProof(4, 6, $root1, $root2, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testGetConsistencyProofInvalidOldSize(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);

        // oldSize > newSize should return empty proof
        $proof = $tree->getConsistencyProof(10);
        $this->assertEmpty($proof->proof);

        // oldSize <= 0 should return empty proof
        $proof2 = $tree->getConsistencyProof(0);
        $this->assertEmpty($proof2->proof);

        $proof3 = $tree->getConsistencyProof(-1);
        $this->assertEmpty($proof3->proof);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testGetConsistencyProofSameSize(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);
        $proof = $tree->getConsistencyProof(3);
        $this->assertEmpty($proof->proof);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofVariousSizes(string $hashAlg): void
    {
        // Test with various tree sizes to exercise different code paths
        foreach ([2, 3, 4, 5, 7, 8, 9, 15, 16, 17] as $size) {
            $leaves = array_map(fn($i) => "leaf$i", range(0, $size - 1));
            $tree = new Tree($leaves, $hashAlg);
            $root = $tree->getRoot();
            $this->assertNotNull($root);

            // Test first, middle, and last leaf
            foreach ([0, (int)($size / 2), $size - 1] as $idx) {
                $proof = $tree->getInclusionProof($leaves[$idx]);
                $this->assertTrue(
                    $tree->verifyInclusionProof($root, $leaves[$idx], $proof),
                    "Failed for size=$size, idx=$idx"
                );
            }
        }
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProofVariousSizes(string $hashAlg): void
    {
        // Create a large tree
        $allLeaves = array_map(fn($i) => "leaf$i", range(0, 16));
        $fullTree = new Tree($allLeaves, $hashAlg);
        $fullRoot = $fullTree->getRoot();
        $this->assertNotNull($fullRoot);

        // Test consistency from various old sizes
        foreach ([1, 2, 3, 4, 5, 7, 8, 9, 15, 16] as $oldSize) {
            $oldLeaves = array_slice($allLeaves, 0, $oldSize);
            $oldTree = new Tree($oldLeaves, $hashAlg);
            $oldRoot = $oldTree->getRoot();
            $this->assertNotNull($oldRoot);

            $proof = $fullTree->getConsistencyProof($oldSize);
            $this->assertTrue(
                $fullTree->verifyConsistencyProof($oldSize, 17, $oldRoot, $fullRoot, $proof),
                "Failed for oldSize=$oldSize"
            );
        }
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testEmptySubtreeRoot(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);

        // The encoded root for an empty tree should be all zeros
        $emptyTree = new Tree([], $hashAlg);
        $encodedEmpty = $emptyTree->getEncodedRoot();
        $this->assertStringContainsString('AAAA', $encodedEmpty);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testAddLeafUpdatesRoot(string $hashAlg): void
    {
        $tree = new Tree([], $hashAlg);
        $this->assertNull($tree->getRoot());

        $tree->addLeaf('first');
        $root1 = $tree->getRoot();
        $this->assertNotNull($root1);

        $tree->addLeaf('second');
        $root2 = $tree->getRoot();
        $this->assertNotNull($root2);
        $this->assertNotEquals($root1, $root2);

        // Compare with fresh tree
        $freshTree = new Tree(['first', 'second'], $hashAlg);
        $this->assertEquals($freshTree->getRoot(), $root2);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testHashFunctions(string $hashAlg): void
    {
        $tree = new Tree([], $hashAlg);

        // Test hashLeaf produces different results for different inputs
        $hash1 = $tree->hashLeaf('a');
        $hash2 = $tree->hashLeaf('b');
        $this->assertNotEquals($hash1, $hash2);

        // Test hashNode produces different results for different order
        $nodeHash1 = $tree->hashNode($hash1, $hash2);
        $nodeHash2 = $tree->hashNode($hash2, $hash1);
        $this->assertNotEquals($nodeHash1, $nodeHash2);

        // Verify hash length is appropriate for algorithm
        $expectedLength = match($hashAlg) {
            'blake2b', 'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => strlen(hash($hashAlg, '', true)),
        };
        $this->assertEquals($expectedLength, strlen($hash1));
    }

    /**
     * @throws SodiumException
     */
    public function testHashAlgorithmSpecificEncoding(): void
    {
        $leaves = ['test'];

        // Each algorithm produces different encoded root length
        $sha256Tree = new Tree($leaves, 'sha256');
        $sha256Root = $sha256Tree->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $sha256Root);
        $this->assertEquals(53, strlen($sha256Root)); // 10 + 43

        $sha384Tree = new Tree($leaves, 'sha384');
        $sha384Root = $sha384Tree->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $sha384Root);
        $this->assertEquals(74, strlen($sha384Root)); // 10 + 64

        $sha512Tree = new Tree($leaves, 'sha512');
        $sha512Root = $sha512Tree->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $sha512Root);
        $this->assertEquals(96, strlen($sha512Root)); // 10 + 86

        $blake2bTree = new Tree($leaves, 'blake2b');
        $blake2bRoot = $blake2bTree->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $blake2bRoot);
        $this->assertEquals(53, strlen($blake2bRoot)); // 10 + 43

        $this->assertNotEquals($sha256Root, $sha384Root);
        $this->assertNotEquals($sha384Root, $sha512Root);
        $this->assertNotEquals($sha256Root, $blake2bRoot);
    }

    public static function inclusionProofKnownAnswers(): array
    {
        return [
            [
                'blake2b',
                [
                    'a' => [
                        '{"index":0,"proof":[]}',
                        '7234082e1dd0b5ec0acd71875d61c9f374af30c100bc4de7aa4eb3f15bbed686'
                    ],
                    'b' => [
                        '{"index":1,"proof":["cjQILh3QtewKzXGHXWHJ83SvMMEAvE3nqk6z8Vu-1oY"]}',
                        'ee616625a590167bc4b3dc703ab4f3f2ddecbee6b9d05fee9281f02046e6082e'
                    ],
                    'c' => [
                        '{"index":2,"proof":["7mFmJaWQFnvEs9xwOrTz8t3svua50F_ukoHwIEbmCC4"]}',
                        '17321db51c1ef3ec1f77e271aa300b4e5c6091708bcba37e46025774a26142ee'
                    ],
                    'd' => [
                        '{"index":3,"proof":["lgJZ9cCIXnt5Z8wlFYvJBp2xyoIi577_3__l3qApeWY","7mFmJaWQFnvEs9xwOrTz8t3svua50F_ukoHwIEbmCC4"]}',
                        '421360a6099803b465dff5246cb164c2b6ffac54f17cecc04fa7bfe2561e1804'
                    ],
                    'e' => [
                        '{"index":4,"proof":["QhNgpgmYA7Rl3_UkbLFkwrb_rFTxfOzAT6e_4lYeGAQ"]}',
                        '57d36622e3f900dadd327fb108b62e282cb8f65225ff24749df78d09176c1d0d'
                    ],
                    'f' => [
                        '{"index":5,"proof":["P7RYLohVATQBhJerlYZRzce3LT4uATAbP0T4um6CGng","QhNgpgmYA7Rl3_UkbLFkwrb_rFTxfOzAT6e_4lYeGAQ"]}',
                        'a4f7cb64de6f9e72ada77332765140211fb9e5af31d7457f8a4cf5c40603cb74'
                    ],
                    'g' => [
                        '{"index":6,"proof":["S75UXJ1lbLGRniGEiF3n1sOaGpj8wLLvQu5Nmc6En7s","QhNgpgmYA7Rl3_UkbLFkwrb_rFTxfOzAT6e_4lYeGAQ"]}',
                        '0ce9bb5a866b32da9bbedf63a975ce8516626b796b5ceae40b9e353c28a49ddf'
                    ],
                    'h' => [
                        '{"index":7,"proof":["gsQMTwLeIdDv0m6o70ZOczKpiD-xQDp38--NP8XRnOA","S75UXJ1lbLGRniGEiF3n1sOaGpj8wLLvQu5Nmc6En7s","QhNgpgmYA7Rl3_UkbLFkwrb_rFTxfOzAT6e_4lYeGAQ"]}',
                        'a383c5b578749fb99e369052a4ddd25afbdb7279fdaa1d7c8b72093be140f437'
                    ],
                ]
            ], [
                'sha256',
                [
                    'a' => [
                        '{"index":0,"proof":[]}',
                        '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'
                    ],
                    'b' => [
                        '{"index":1,"proof":["Aippeebat6pa5MPl5F9-l3ESp-Y1k4INvsHsc4ok-Tw"]}',
                        'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb'
                    ],
                    'c' => [
                        '{"index":2,"proof":["sTeYX_SE-2ANuTEHx3sDZcgNePW0Kd7Q_Zc2HQd5mes"]}',
                        '36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1'
                    ],
                    'd' => [
                        '{"index":3,"proof":["WX_LMSgtNGVMIA00GPylcFxkjr8ybsc9jd7xGEH4dtg","sTeYX_SE-2ANuTEHx3sDZcgNePW0Kd7Q_Zc2HQd5mes"]}',
                        '33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0'
                    ],
                    'e' => [
                        '{"index":4,"proof":["MzdqO9Y-mZNwioTd_mworli4NQXdH-1xG9kk7FpiOfA"]}',
                        'fe14a5426fbd70c0fa73f52342afed0da0bd23c4838662ccf6b88a3070ead97b'
                    ],
                    'f' => [
                        '{"index":5,"proof":["KCSnzNosqnIMhcn7oei1tzXuz9sDh45Pjf5sNiUDC8Q","MzdqO9Y-mZNwioTd_mworli4NQXdH-1xG9kk7FpiOfA"]}',
                        'e069fc12e231ccfd4516bf1617945fb3ccd5cc8910d92d6265289f088f777fdd'
                    ],
                    'g' => [
                        '{"index":6,"proof":["kYVmGEydW-I1rStt1ggo9c7BT8QJ8C99uGRwCextpYg","MzdqO9Y-mZNwioTd_mworli4NQXdH-1xG9kk7FpiOfA"]}',
                        '4ae191939f548d9934740b88dea2c5cb89bb8870fc4505cd79dec6bbfaaee9cb'
                    ],
                    'h' => [
                        '{"index":7,"proof":["WusZboNZgjG0XGHz4MWg_aSbDU-GpttfiTqszPUU-pk","kYVmGEydW-I1rStt1ggo9c7BT8QJ8C99uGRwCextpYg","MzdqO9Y-mZNwioTd_mworli4NQXdH-1xG9kk7FpiOfA"]}',
                        'a5dac6b1ff1dca13dcf9423dcbf1bbb4dbce7e8cbf7f4c014cf40c6c8171a2bd'
                    ],
                ]
            ], [
                'sha384',
                [
                    'a' => [
                        '{"index":0,"proof":[]}',
                        'f5077c4b6e328b21e2f21192776daf9660ceaeaf40a1796b58bd9500b36aff2cb5acd79d2789f891541818315233ff6c'
                    ],
                    'b' => [
                        '{"index":1,"proof":["9Qd8S24yiyHi8hGSd22vlmDOrq9AoXlrWL2VALNq_yy1rNedJ4n4kVQYGDFSM_9s"]}',
                        '26e9d850dd820b5bdc2222dcc574968efd2ea2ccaab694b444c48f479d31c395d6a8da9dfe865ceda1e3a89ac3a64470'
                    ],
                    'c' => [
                        '{"index":2,"proof":["JunYUN2CC1vcIiLcxXSWjv0uosyqtpS0RMSPR50xw5XWqNqd_oZc7aHjqJrDpkRw"]}',
                        'f558be2464938cd3266e7a25cc876fd6697768c8a8d312fb7013d006ab98686937d89ad92547b429ad69264c11fc538b'
                    ],
                    'd' => [
                        '{"index":3,"proof":["gQNVFRDvF5fn2j-h2jDofg7pibtU-mr5iYiyZTd6jdxDuU_iOLWPPNWrfEspbcuY","JunYUN2CC1vcIiLcxXSWjv0uosyqtpS0RMSPR50xw5XWqNqd_oZc7aHjqJrDpkRw"]}',
                        '45b0cb2921be9c937ffb1e4fa870d03762780d56b1c0b32b805d0ba826b0915ed3eb39e6cb78831be4d7277d86e0271c'
                    ],
                    'e' => [
                        '{"index":4,"proof":["RbDLKSG-nJN_-x5PqHDQN2J4DVaxwLMrgF0LqCawkV7T6znmy3iDG-TXJ32G4Ccc"]}',
                        '356823f59915bc43d2623552360ce1438e63fcd4225660ed98814d627d79feaa7db47e31c0e9bf42ea98384073ca4133'
                    ],
                    'f' => [
                        '{"index":5,"proof":["FPTQAubLIc-hxnxcnUsQlmQqoJkbO___ixs0wyV8-iG-ZyLeA79gg_wIxkDx4rNR","RbDLKSG-nJN_-x5PqHDQN2J4DVaxwLMrgF0LqCawkV7T6znmy3iDG-TXJ32G4Ccc"]}',
                        '627dd6aaedb041a3c0a2ed850ae6fd42d58a3286418c7eec98b42a2674d0c0d41908547400f80457c1e8142e025d7109'
                    ],
                    'g' => [
                        '{"index":6,"proof":["uGAKnanHJ5163HHlBMLOTDZxU8F68GIhoqd7KbMcSO1IDHdNGXrMH8tvEDXIPx3r","RbDLKSG-nJN_-x5PqHDQN2J4DVaxwLMrgF0LqCawkV7T6znmy3iDG-TXJ32G4Ccc"]}',
                        '4a2cbeaf057493c02492feedf38e78af7b824ed06a884f8772542e54b38c0d02f4b58eb1f8b844f36f12c3db4bd912f1'
                    ],
                    'h' => [
                        '{"index":7,"proof":["CsL2CbLtkmzEJigB4FJkw32SQqjUiYDR-hTFqMN4plqs0K39aeqgaeCmJhYR4udC","uGAKnanHJ5163HHlBMLOTDZxU8F68GIhoqd7KbMcSO1IDHdNGXrMH8tvEDXIPx3r","RbDLKSG-nJN_-x5PqHDQN2J4DVaxwLMrgF0LqCawkV7T6znmy3iDG-TXJ32G4Ccc"]}',
                        'b185df41b8715d3290fb575bec47150736f77417ad8eb7ad8f474eba4cf71781e5da4018022c7b757b7228314ca18a06'
                    ],
                ]
            ], [
                'sha512',
                [
                    'a' => [
                        '{"index":0,"proof":[]}',
                        '031ab9ff5962e81139a6900216945fc584ab186aeb1bf3498c661b976a7393af94b6bcc9784f7e8cb75b071de60f9fda06d44ddd561e53e3343857eea2089217'
                    ],
                    'b' => [
                        '{"index":1,"proof":["Axq5_1li6BE5ppACFpRfxYSrGGrrG_NJjGYbl2pzk6-UtrzJeE9-jLdbBx3mD5_aBtRN3VYeU-M0OFfuogiSFw"]}',
                        '4b46df98b7104978e58a14ed3d5febb89bb2327ffce4307b55254ae8b26e76bf251dec7ea1111502a142e2eadf5a8ebbdece4b3a519c7cf3c781144f2a38f2cf'
                    ],
                    'c' => [
                        '{"index":2,"proof":["S0bfmLcQSXjlihTtPV_ruJuyMn_85DB7VSVK6LJudr8lHex-oREVAqFC4urfWo673s5LOlGcfPPHgRRPKjjyzw"]}',
                        '8312813c8b27697db9eb313fca312ff54a9f5411dd702e16dde081c0493856aa0624d4689c6f37569e9dd3e2920952c655ed46a4e75b0534fcbe8a6cfdbcad2d'
                    ],
                    'd' => [
                        '{"index":3,"proof":["F9epsRtIpTFISg-3xY9mV0ksn8jUrax65-lmgHoGmOARdpdc9ahrTCS8R_J3sQ03cHkXBs8NIq9sTD53Lf3CUw","S0bfmLcQSXjlihTtPV_ruJuyMn_85DB7VSVK6LJudr8lHex-oREVAqFC4urfWo673s5LOlGcfPPHgRRPKjjyzw"]}',
                        '262521310fc23d0970feddf334dfffcfc80dacee9de05463957ab9a092451f73ca2b48c5eb57ae74d06aee9c7d3035af5811da0fc9c1df3b7ee439a495f684ae'
                    ],
                    'e' => [
                        '{"index":4,"proof":["JiUhMQ_CPQlw_t3zNN__z8gNrO6d4FRjlXq5oJJFH3PKK0jF61eudNBq7px9MDWvWBHaD8nB3zt-5DmklfaErg"]}',
                        '884eff5a51008a015539b06b3c841ec3f4bb16c8fd4751165e902b2cd0967e81f9d17fa1d1ee0b96fabe67ccb8c183d828ed664c62f403980dfde1dd31d6997e'
                    ],
                    'f' => [
                        '{"index":5,"proof":["S8UMmw2FFdPqrh50spqVgENGxJHuGpW_JeSquFSmplEe63M4f5aw51NoMGZLkHPmbi_yuZYjdzeTBIYK77XpxQ","JiUhMQ_CPQlw_t3zNN__z8gNrO6d4FRjlXq5oJJFH3PKK0jF61eudNBq7px9MDWvWBHaD8nB3zt-5DmklfaErg"]}',
                        '5dce57dce63ae6ff585438efdb6b0f5b6cc0a735699754b33081bfadb7ea22b463f92c37afa4f526ba5ecedb8058cb967325fda8fda7120cd5f13443256ea2c8'
                    ],
                    'g' => [
                        '{"index":6,"proof":["31hAmcg7CWLAHHGgB68x3-jMBBRFVIHSLTAhwWB360VjQ3-60ck71q_tnEE71mvuawzhR38avfkixgCasQyqgQ","JiUhMQ_CPQlw_t3zNN__z8gNrO6d4FRjlXq5oJJFH3PKK0jF61eudNBq7px9MDWvWBHaD8nB3zt-5DmklfaErg"]}',
                        '02860da86ce764a24c4e6859000d19aff410de08326c92076eb985bd73add469dfaf6da71175160f56a9013eafbdeb6dcd11b90f021f913819e1015f45a6c060'
                    ],
                    'h' => [
                        '{"index":7,"proof":["5gWnZ4JcDaSLpijXhULCUMMSBsoNScLi7hkI_YC20G1e1fUxCrCv3xb-d1hIQNyIMKC0t4XE-sQBfornXym70A","31hAmcg7CWLAHHGgB68x3-jMBBRFVIHSLTAhwWB360VjQ3-60ck71q_tnEE71mvuawzhR38avfkixgCasQyqgQ","JiUhMQ_CPQlw_t3zNN__z8gNrO6d4FRjlXq5oJJFH3PKK0jF61eudNBq7px9MDWvWBHaD8nB3zt-5DmklfaErg"]}',
                        '9aeb807820475c984669d2c15523ced2fb2d03f72b581a358e8ea047f7f625212142a255bef3dfce3d79abf19ac6e8d0403c17170b1d1f2d15e24c43cc2c6a58'
                    ],
                ]
            ],
        ];
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("inclusionProofKnownAnswers")]
    public function testInclusionProofAgainstKnownAnswer(string $hashAlgo, array $leavesToAdd): void
    {
        // Start with a blank tree:
        $tree = new Tree([], $hashAlgo);
        foreach ($leavesToAdd as $leaf => $expected) {
            [$expectedJson, $expectedRoot] = $expected;
            $tree->addLeaf($leaf);
            $root = $tree->getRoot();
            $this->assertSame($expectedRoot, sodium_bin2hex($root), 'root for leaf ' . $leaf);

            $proof = $tree->getInclusionProof($leaf);
            $this->assertTrue($tree->verifyInclusionProof($root, $leaf, $proof), 'valid proof: ' . $leaf);
            $this->assertFalse($tree->verifyInclusionProof($root, 'wrong' . $leaf, $proof), 'invalid proof: ' . $leaf);
            $encoded = json_encode($proof);
            $this->assertSame($expectedJson, $encoded, 'inclusion json: ' . $leaf);
        }
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyInclusionProofWithWrongProof(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        // Get proof for 'a' but verify with 'h'
        $proofForA = $tree->getInclusionProof('a');
        $this->assertFalse($tree->verifyInclusionProof($root, 'h', $proofForA));

        // Get proof for last element, verify with first
        $proofForH = $tree->getInclusionProof('h');
        $this->assertFalse($tree->verifyInclusionProof($root, 'a', $proofForH));
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofEdgeCases(string $hashAlg): void
    {
        // Single element tree - proof should be empty and valid
        $singleTree = new Tree(['only'], $hashAlg);
        $singleRoot = $singleTree->getRoot();
        $this->assertNotNull($singleRoot);

        $singleProof = $singleTree->getInclusionProof('only');
        $this->assertEmpty($singleProof->proof);
        $this->assertTrue($singleTree->verifyInclusionProof($singleRoot, 'only', $singleProof));

        // Two element tree - proof should have one element
        $twoTree = new Tree(['first', 'second'], $hashAlg);
        $twoRoot = $twoTree->getRoot();
        $this->assertNotNull($twoRoot);

        $firstProof = $twoTree->getInclusionProof('first');
        $this->assertCount(1, $firstProof->proof);
        $this->assertTrue($twoTree->verifyInclusionProof($twoRoot, 'first', $firstProof));

        $secondProof = $twoTree->getInclusionProof('second');
        $this->assertCount(1, $secondProof->proof);
        $this->assertTrue($twoTree->verifyInclusionProof($twoRoot, 'second', $secondProof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testGetConsistencyProofSameSizeReturnsEmpty(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd'], $hashAlg);

        $proof = $tree->getConsistencyProof(4);
        $this->assertInstanceOf(ConsistencyProof::class, $proof);
        $this->assertEmpty($proof->proof);

        $root = $tree->getRoot();
        $this->assertNotNull($root);
        $this->assertTrue($tree->verifyConsistencyProof(4, 4, $root, $root, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofOldSizeValidation(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd', 'e'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proof = new ConsistencyProof([]);
        $this->assertFalse($tree->verifyConsistencyProof(10, 5, $root, $root, $proof));
        $this->assertFalse($tree->verifyConsistencyProof(-1, 5, $root, $root, $proof));
        $this->assertTrue($tree->verifyConsistencyProof(0, 5, null, $root, $proof));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofIndexBoundary(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);

        $proofAtBoundary = new InclusionProof(4, []);
        $result = $tree->verifyInclusionProof($root, 'a', $proofAtBoundary);
        $this->assertIsBool($result);
        $this->assertFalse($result);

        $proofLastValid = new InclusionProof(3, []);

        $this->assertFalse($tree->verifyInclusionProof($root, 'd', $proofLastValid));
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testGetConsistencyProofBoundary(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c', 'd', 'e'], $hashAlg);

        $proof = $tree->getConsistencyProof(10);
        $this->assertInstanceOf(ConsistencyProof::class, $proof);
        $this->assertEmpty($proof->proof);

        $proof0 = $tree->getConsistencyProof(0);
        $this->assertEmpty($proof0->proof);

        $proofEqual = $tree->getConsistencyProof(5);
        $this->assertEmpty($proofEqual->proof);

        $proofValid = $tree->getConsistencyProof(3);
        $this->assertNotEmpty($proofValid->proof);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofSizeValidation(string $hashAlg): void
    {
        $tree = new Tree(['a', 'b', 'c'], $hashAlg);
        $root = $tree->getRoot();
        $this->assertNotNull($root);
        $proof = new ConsistencyProof([]);

        $this->assertFalse(
            $tree->verifyConsistencyProof(5, 3, $root, $root, $proof)
        );

        $this->assertFalse(
            $tree->verifyConsistencyProof(-1, 3, $root, $root, $proof)
        );

        $this->assertFalse(
            $tree->verifyConsistencyProof(-5, 3, $root, $root, $proof)
        );

        $this->assertTrue(
            $tree->verifyConsistencyProof(0, 3, null, $root, $proof)
        );
    }

    public function testGetSplitPointSmallValues(): void
    {
        $this->assertSame(0, Tree::getSplitPoint(0));
        $this->assertSame(0, Tree::getSplitPoint(1));
        $this->assertSame(1, Tree::getSplitPoint(2));
        $this->assertSame(2, Tree::getSplitPoint(3));
        $this->assertSame(2, Tree::getSplitPoint(4));
        $this->assertSame(4, Tree::getSplitPoint(5));
        $this->assertSame(4, Tree::getSplitPoint(6));
        $this->assertSame(4, Tree::getSplitPoint(7));
        $this->assertSame(4, Tree::getSplitPoint(8));
        $this->assertSame(8, Tree::getSplitPoint(9));
        // ... snip ...
        $this->assertSame(8, Tree::getSplitPoint(14));
        $this->assertSame(8, Tree::getSplitPoint(15));
        $this->assertSame(8, Tree::getSplitPoint(16));
        $this->assertSame(16, Tree::getSplitPoint(17));
        // ... snip ...
        $this->assertSame(16, Tree::getSplitPoint(32));
        $this->assertSame(32, Tree::getSplitPoint(33));
        // ... snip ...
        $this->assertSame(32, Tree::getSplitPoint(64));
        $this->assertSame(64, Tree::getSplitPoint(65));
    }

    public function testIsHashFunctionAllowedReturnType(): void
    {
        $resultValid = Tree::isHashFunctionAllowed('sha256');
        $this->assertIsBool($resultValid);
        $this->assertTrue($resultValid);

        $resultInvalid = Tree::isHashFunctionAllowed('md5');
        $this->assertIsBool($resultInvalid);
        $this->assertFalse($resultInvalid);

        $resultUnknown = Tree::isHashFunctionAllowed('not-a-hash');
        $this->assertIsBool($resultUnknown);
        $this->assertFalse($resultUnknown);
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testVerifyConsistencyProofFinalCheck(string $hashAlg): void
    {
        // Create two related trees
        $smallTree = new Tree(['a', 'b', 'c'], $hashAlg);
        $smallRoot = $smallTree->getRoot();
        $this->assertNotNull($smallRoot);

        $largeTree = new Tree(['a', 'b', 'c', 'd', 'e'], $hashAlg);
        $largeRoot = $largeTree->getRoot();
        $this->assertNotNull($largeRoot);

        $proof = $largeTree->getConsistencyProof(3);

        $this->assertTrue($largeTree->verifyConsistencyProof(3, 5, $smallRoot, $largeRoot, $proof));
        $wrongOldRoot = str_repeat("\x00", strlen($smallRoot));
        $this->assertFalse($largeTree->verifyConsistencyProof(3, 5, $wrongOldRoot, $largeRoot, $proof));
        $wrongNewRoot = str_repeat("\x00", strlen($largeRoot));
        $this->assertFalse($largeTree->verifyConsistencyProof(3, 5, $smallRoot, $wrongNewRoot, $proof));
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testInclusionProofVerificationLoops(string $hashAlg): void
    {
        foreach ([2, 3, 4, 5, 6, 7, 8, 9] as $size) {
            $leaves = array_map(fn($i) => "leaf$i", range(0, $size - 1));
            $tree = new Tree($leaves, $hashAlg);
            $root = $tree->getRoot();
            $this->assertNotNull($root);

            // Verify all leaves
            for ($i = 0; $i < $size; $i++) {
                $proof = $tree->getInclusionProof($leaves[$i]);
                $this->assertTrue(
                    $tree->verifyInclusionProof($root, $leaves[$i], $proof),
                    "Failed for size=$size, index=$i"
                );
            }
        }
    }

    /**
     * @throws SodiumException
     */
    #[DataProvider("hashAlgProvider")]
    public function testConsistencyProofPowerOfTwoSizes(string $hashAlg): void
    {
        // Powers of two have special handling
        foreach ([2, 4, 8, 16, 32] as $powerOfTwo) {
            $leaves = array_map(fn($i) => "leaf$i", range(0, $powerOfTwo + 2));
            $fullTree = new Tree($leaves, $hashAlg);
            $fullRoot = $fullTree->getRoot();

            $smallLeaves = array_slice($leaves, 0, $powerOfTwo);
            $smallTree = new Tree($smallLeaves, $hashAlg);
            $smallRoot = $smallTree->getRoot();

            $proof = $fullTree->getConsistencyProof($powerOfTwo);
            $this->assertTrue(
                $fullTree->verifyConsistencyProof(
                    $powerOfTwo,
                    count($leaves),
                    $smallRoot,
                    $fullRoot,
                    $proof
                ),
                "Failed for power of two: $powerOfTwo"
            );
        }
    }

    /**
     * @throws SodiumException
     */
    public function testGetEncodedRootHashLengths(): void
    {
        $treeSha256 = new Tree([], 'sha256');
        $encoded256 = $treeSha256->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $encoded256);
        $encodedPart256 = substr($encoded256, 10);
        $decoded256 = Base64UrlSafe::decodeNoPadding($encodedPart256);
        $this->assertSame(32, strlen($decoded256), 'sha256 should produce 32-byte hash');

        $treeSha384 = new Tree([], 'sha384');
        $encoded384 = $treeSha384->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $encoded384);
        $encodedPart384 = substr($encoded384, 10);
        $decoded384 = Base64UrlSafe::decodeNoPadding($encodedPart384);
        $this->assertSame(48, strlen($decoded384), 'sha384 should produce 48-byte hash');

        $treeSha512 = new Tree([], 'sha512');
        $encoded512 = $treeSha512->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $encoded512);
        $encodedPart512 = substr($encoded512, 10);
        $decoded512 = Base64UrlSafe::decodeNoPadding($encodedPart512);
        $this->assertSame(64, strlen($decoded512), 'sha512 should produce 64-byte hash');

        $treeBlake = new Tree([], 'blake2b');
        $encodedBlake = $treeBlake->getEncodedRoot();
        $this->assertStringStartsWith('pkd-mr-v1:', $encodedBlake);
        $encodedPartBlake = substr($encodedBlake, 10);
        $decodedBlake = Base64UrlSafe::decodeNoPadding($encodedPartBlake);
        $this->assertSame(32, strlen($decodedBlake), 'blake2b should produce 32-byte hash');
    }

    /**
     * @throws SodiumException
     */
    public function testVerifyInclusionProofIndexEqualToSize(): void
    {
        $leaves = ['a', 'b', 'c'];
        $tree = new Tree($leaves);
        $root = $tree->getRoot();
        $this->assertNotNull($root);
        $invalidProof = new InclusionProof(3, []); // index 3 for size 3
        $result = $tree->verifyInclusionProof($root, 'a', $invalidProof);
        $this->assertFalse($result, 'Proof with index === size should be rejected');
    }

    /**
     * @throws SodiumException
     */
    public function testVerifyInclusionProofIndexGreaterThanSize(): void
    {
        $leaves = ['a', 'b'];
        $tree = new Tree($leaves);
        $root = $tree->getRoot();
        $this->assertNotNull($root);
        $invalidProof = new InclusionProof(5, []);
        $result = $tree->verifyInclusionProof($root, 'a', $invalidProof);
        $this->assertFalse($result, 'Proof with index > size should be rejected');
    }

    /**
     * @throws SodiumException
     */
    public function testConsistencyProofOldSizeEqualsNewSize(): void
    {
        $leaves = ['a', 'b', 'c'];
        $tree = new Tree($leaves);
        $proof = $tree->getConsistencyProof(3);
        $this->assertInstanceOf(ConsistencyProof::class, $proof);
        $this->assertEmpty($proof->proof, 'Consistency proof should be empty when old size === new size');
    }

    /**
     * @throws SodiumException
     */
    public function testConsistencyProofOldSizeGreaterThanNewSize(): void
    {
        $leaves = ['a', 'b'];
        $tree = new Tree($leaves);
        $proof = $tree->getConsistencyProof(5);
        $this->assertInstanceOf(ConsistencyProof::class, $proof);
        $this->assertEmpty($proof->proof, 'Consistency proof should be empty when old size > new size');
    }
}
