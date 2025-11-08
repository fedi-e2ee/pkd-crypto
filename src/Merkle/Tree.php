<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use ParagonIE\ConstantTime\Base64UrlSafe;
use FediE2EE\PKD\Crypto\{
    UtilTrait,
    Exceptions\CryptoException
};
use SodiumException;

/**
 * This is a Merkle Tree implementation that follows RFC 9162.
 * @link https://datatracker.ietf.org/doc/html/rfc9162
 * @api
 */
class Tree
{
    use UtilTrait;
    private array $leaves = [];
    private ?string $root = null;
    private string $hashAlgo;

    /**
     * @param string[] $leaves Leaves to insert
     * @param string $hashAlgo Hash function algorithm
     * @throws SodiumException
     */
    public function __construct(
        array          $leaves = [],
        string $hashAlgo = 'sha256'
    ) {
        $this->hashAlgo = $hashAlgo;
        if (!empty($leaves)) {
            foreach ($leaves as $leaf) {
                $this->leaves[] = $this->hashLeaf($leaf);
            }
            $this->root = $this->getRootForSubtree(0, count($this->leaves));
        }
    }

    /**
     * @throws SodiumException
     * @api
     */
    public function addLeaf(string $leaf): void
    {
        $this->leaves[] = $this->hashLeaf($leaf);
        $this->root = $this->getRootForSubtree(0, count($this->leaves));
    }

    public function updateRoot(): void
    {
        $this->root = $this->getRootForSubtree(0, count($this->leaves));
    }

    public function getRoot(): ?string
    {
        return $this->root;
    }

    /**
     * @api
     */
    public function getEncodedRoot(): string
    {
        $hashLength = match($this->hashAlgo) {
            'sha256', 'blake2b' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => strlen(hash($this->hashAlgo, '', true)),
        };
        // Default according to spec:
        if (is_null($this->root)) {
            return 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\0", $hashLength));
        }
        return 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded($this->root);
    }

    public function getSize(): int
    {
        return count($this->leaves);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function getInclusionProof(string $leaf): InclusionProof
    {
        $leafHash = $this->hashLeaf($leaf);
        $index = array_search($leafHash, $this->leaves, true);
        if ($index === false) {
            throw new CryptoException('Could not find index in leaves');
        }

        return new InclusionProof(
            $index,
            $this->generateInclusionSubProof($index, 0, count($this->leaves))
        );
    }

    /**
     * @throws SodiumException
     */
    private function generateInclusionSubProof(int $index, int $start, int $end): array
    {
        $leafCount = $end - $start;
        if ($leafCount <= 1) {
            return [];
        }
        $k = self::getSplitPoint($leafCount);

        if ($index < ($start + $k)) {
            $proof = $this->generateInclusionSubProof($index, $start, $start + $k);
            $proof[] = $this->getRootForSubtree($start + $k, $end);
            return $proof;
        }
        $proof = $this->generateInclusionSubProof($index, $start + $k, $end);
        $proof[] = $this->getRootForSubtree($start, $start + $k);
        return $proof;
    }

    /**
     * @throws SodiumException
     */
    public function verifyInclusionProof(string $root, string $leaf, InclusionProof $proof): bool
    {
        if ($proof->index >= $this->getSize()) {
            return false;
        }

        $fn = $proof->index;
        $sn = $this->getSize() - 1;
        $r = $this->hashLeaf($leaf);

        foreach ($proof->proof as $p) {
            if ($sn === 0) {
                return false;
            }
            if (($fn & 1) === 1 || $fn === $sn) {
                $r = $this->hashNode($p, $r);
                while ((($fn & 1) === 0) && $fn !== 0) {
                    $fn >>= 1;
                    $sn >>= 1;
                }
            } else {
                $r = $this->hashNode($r, $p);
            }
            $fn >>= 1;
            $sn >>= 1;
        }

        return $sn === 0 && hash_equals($root, $r);
    }

    /**
     * @throws SodiumException
     * @api
     */
    public function getConsistencyProof(int $oldSize): ConsistencyProof
    {
        $newSize = $this->getSize();
        if ($oldSize > $newSize || $oldSize <= 0) {
            return new ConsistencyProof([]);
        }
        if ($oldSize === $newSize) {
            return new ConsistencyProof([]);
        }
        return new ConsistencyProof(
            $this->generateConsistencySubProof($oldSize, 0, $newSize, true)
        );
    }

    /**
     * @throws SodiumException
     */
    private function generateConsistencySubProof(int $m, int $start, int $end, bool $isRoot): array
    {
        $n = $end - $start;
        if ($m === $n) {
            if ($isRoot) {
                return [];
            }
            return [$this->getRootForSubtree($start, $end)];
        }
        $k = self::getSplitPoint($n);

        if ($m <= $k) {
            $proof = $this->generateConsistencySubProof($m, $start, $start + $k, $isRoot);
            $proof[] = $this->getRootForSubtree($start + $k, $end);
            return $proof;
        }
        $proof = $this->generateConsistencySubProof($m - $k, $start + $k, $end, false);
        $proof[] = $this->getRootForSubtree($start, $start + $k);
        return $proof;
    }

    /**
     * @throws SodiumException
     */
    private function getRootForSubtree(int $start, int $end): string
    {
        $leafCount = $end - $start;
        if ($leafCount < 1) {
            if ($this->hashAlgo === 'blake2b') {
                return sodium_crypto_generichash('');
            }
            return hash($this->hashAlgo, '', true);
        }
        if ($leafCount === 1) {
            return $this->leaves[$start];
        }

        $k = self::getSplitPoint($leafCount);
        $left = $this->getRootForSubtree($start, $start + $k);
        $right = $this->getRootForSubtree($start + $k, $end);
        return $this->hashNode($left, $right);
    }

    /**
     * @throws SodiumException
     */
    public function verifyConsistencyProof(
        int $oldSize,
        int $newSize,
        ?string $oldRoot,
        string $newRoot,
        ConsistencyProof $proof
    ): bool {
        if ($oldSize > $newSize || $oldSize < 0) {
            return false;
        }
        if ($oldSize === $newSize) {
            return empty($proof->proof) && hash_equals((string) $oldRoot, $newRoot);
        }
        if ($oldSize === 0) {
            return empty($proof->proof);
        }
        if ($oldRoot === null) {
            return false;
        }
        if (empty($proof->proof)) {
            return false;
        }

        $consistencyProof = $proof->proof;
        if (($oldSize & ($oldSize - 1)) === 0) {
            array_unshift($consistencyProof, $oldRoot);
        }

        $fn = $oldSize - 1;
        $sn = $newSize - 1;

        if (($fn & 1) === 1) {
            while ((($fn & 1) === 1)) {
                $fn >>= 1;
                $sn >>= 1;
            }
        }

        $fr = $consistencyProof[0];
        $sr = $consistencyProof[0];

        for ($i = 1; $i < count($consistencyProof); ++$i) {
            $c = $consistencyProof[$i];
            if ($sn === 0) {
                return false;
            }
            if (($fn & 1) === 1 || ($fn === $sn)) {
                $fr = $this->hashNode($c, $fr);
                $sr = $this->hashNode($c, $sr);
                while ((($fn & 1) === 0) && $fn !== 0) {
                    $fn >>= 1;
                    $sn >>= 1;
                }
            } else {
                $sr = $this->hashNode($sr, $c);
            }
            $fn >>= 1;
            $sn >>= 1;
        }

        return hash_equals($oldRoot, $fr)
            && hash_equals($newRoot, $sr)
            && ($sn === 0);
    }

    /**
     * @throws SodiumException
     */
    public function hashLeaf(string $leaf): string
    {
        if ($this->hashAlgo === 'blake2b') {
            return sodium_crypto_generichash("\x00" . $leaf);
        }
        return hash($this->hashAlgo, "\x00" . $leaf, true);
    }

    /**
     * @throws SodiumException
     */
    public function hashNode(string $left, string $right): string
    {
        if ($this->hashAlgo === 'blake2b') {
            return sodium_crypto_generichash("\x01" . $left . $right);
        }
        return hash($this->hashAlgo, "\x01" . $left . $right, true);
    }

    /**
     * Get the largest power of 2 smaller than $n.
     *
     * @param int $n
     * @return int
     */
    protected static function getSplitPoint(int $n): int
    {
        if ($n < 2) {
            return 0;
        }
        $k = 1;
        while ($k < $n) {
            $k <<= 1;
        }
        return $k >> 1;
    }
}
