<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\AttributeEncryption;

use FediE2EE\PKD\Crypto\SymmetricKey;

/**
 * @api
 */
interface AttributeVersionInterface
{
    public function getPlaintextCommitment(
        string $attributeName,
        string $plaintext,
        string $merkleRoot,
        string $salt
    ): string;

    public function encryptAttribute(
        string $attributeName,
        string $plaintext,
        SymmetricKey $ikm,
        string $merkleRoot
    ): string;

    public function decryptAttribute(
        string $attributeName,
        string $ciphertext,
        SymmetricKey $ikm,
        string $merkleRoot
    ): string;
}
