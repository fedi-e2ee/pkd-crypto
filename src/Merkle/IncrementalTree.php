<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Override;
use SodiumException;

/**
 * @api
 */
class IncrementalTree extends Tree
{
    /**
     * @var array<string, string>
     */
    private array $nodes = [];
    private int $size = 0;
    private string $hashAlgo;

    /**
     * @param string[] $leaves Leaves to insert
     * @param string $hashAlgo Hash function algorithm
     * @throws SodiumException
     */
    public function __construct(
        array  $leaves = [],
        string $hashAlgo = 'sha256'
    ) {
        parent::__construct([], $hashAlgo);
        $this->hashAlgo = $hashAlgo;
        if (!empty($leaves)) {
            foreach ($leaves as $leaf) {
                $this->addLeaf($leaf);
            }
        }
    }

    /**
     * @throws SodiumException
     */
    #[Override]
    public function addLeaf(string $leaf): void
    {
        $leafHash = $this->hashLeaf($leaf);
        $index = $this->size;
        $this->nodes["0-{$index}"] = $leafHash;
        $this->size++;

        $level = 0;
        $currentIndex = $index;
        while (true) {
            $siblingIndex = ($currentIndex % 2 === 0) ? $currentIndex + 1 : $currentIndex - 1;
            $siblingKey = "{$level}-{$siblingIndex}";

            if (!isset($this->nodes[$siblingKey])) {
                // Sibling doesn't exist, so we can't calculate the parent yet.
                // In a complete binary tree, this means we are at the edge for this level.
                // The parent will be calculated when the sibling is added.
                break;
            }

            $siblingHash = $this->nodes[$siblingKey];
            $leftHash = ($currentIndex % 2 === 0) ? $leafHash : $siblingHash;
            $rightHash = ($currentIndex % 2 === 0) ? $siblingHash : $leafHash;
            $parentHash = $this->hashNode($leftHash, $rightHash);

            $level++;
            $currentIndex = (int)floor($currentIndex / 2);
            $this->nodes["{$level}-{$currentIndex}"] = $parentHash;
            $leafHash = $parentHash; // The new "leaf" for the next level up.
        }
        $this->updateRoot();
    }

    /**
     * @throws SodiumException
     */
    #[Override]
    public function getRoot(): ?string
    {
        if ($this->size === 0) {
            return null;
        }
        return $this->getRootForSubtree(0, $this->size);
    }

    #[Override]
    public function getSize(): int
    {
        return $this->size;
    }

    /**
     * @throws SodiumException
     */
    private function getRootForSubtree(int $start, int $end): string
    {
        $leafCount = $end - $start;
        if ($leafCount === 0) {
            if ($this->hashAlgo === 'blake2b') {
                return sodium_crypto_generichash('');
            }
            return hash($this->hashAlgo, '', true);
        }
        if ($leafCount === 1) {
            return $this->nodes["0-{$start}"];
        }

        // Check if this subtree corresponds to a pre-calculated node.
        // This is true if its size is a power of two and it's aligned.
        $isPowerOfTwo = ($leafCount > 0) && (($leafCount & ($leafCount - 1)) === 0);
        if ($isPowerOfTwo) {
            $level = (int) log($leafCount, 2);
            // Check for alignment
            if (($start % $leafCount) === 0) {
                $index = $start / $leafCount;
                $key = "{$level}-{$index}";
                if (isset($this->nodes[$key])) {
                    return $this->nodes[$key];
                }
            }
        }

        // If not found in cache, calculate it from children.
        $k = self::getSplitPoint($leafCount);
        $left = $this->getRootForSubtree($start, $start + $k);
        $right = $this->getRootForSubtree($start + $k, $end);

        return $this->hashNode($left, $right);
    }

    public function toJson(): string
    {
        $encodedNodes = [];
        foreach ($this->nodes as $key => $hash) {
            $encodedNodes[$key] = Base64UrlSafe::encode($hash);
        }
        $state = [
            'size' => $this->size,
            'hashAlgo' => $this->hashAlgo,
            'nodes' => $encodedNodes,
        ];
        return json_encode(
            $state,
            JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }

    public static function fromJson(string $json): static
    {
        $state = json_decode($json, true);
        $tree = new static([], $state['hashAlgo']);
        $tree->size = $state['size'];
        foreach ($state['nodes'] as $key => $hash) {
            $tree->nodes[$key] = Base64UrlSafe::decode($hash);
        }
        return $tree;
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[Override]
    public function getInclusionProof(string $leaf): InclusionProof
    {
        $leafHash = $this->hashLeaf($leaf);
        $index = -1;
        // TODO: Consider more efficient techniques
        for ($i = 0; $i < $this->size; $i++) {
            if (hash_equals($this->nodes["0-{$i}"], $leafHash)) {
                $index = $i;
                break;
            }
        }
        if ($index === -1) {
            throw new CryptoException('Could not find index in leaves');
        }

        return new InclusionProof(
            $index,
            $this->generateInclusionSubProof($index, 0, $this->size)
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
        $mid = $start + $k;

        if ($index < $mid) {
            $proof = $this->generateInclusionSubProof($index, $start, $mid);
            $proof[] = $this->getRootForSubtree($mid, $end);
            return $proof;
        }
        $proof = $this->generateInclusionSubProof($index, $mid, $end);
        $proof[] = $this->getRootForSubtree($start, $mid);
        return $proof;
    }
}
