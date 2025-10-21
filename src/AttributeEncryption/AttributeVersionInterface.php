<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\AttributeEncryption;

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
        string $ikm,
        string $merkleRoot
    ): string;

    public function decryptAttribute(
        string $attributeName,
        string $ciphertext,
        string $ikm,
        string $merkleRoot
    ): string;
}
