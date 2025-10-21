<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\AttributeEncryption;

use Exception;
use FediE2EE\PKD\Crypto\UtilTrait;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use SodiumException;

class Version1 implements AttributeVersionInterface
{
    use UtilTrait;

    public const VERSION = "\x01";
    public const KDF_ENCRYPT_KEY = "FediE2EE-v1-Compliance-Encryption-Key";
    public const KDF_AUTH_KEY = "FediE2EE-v1-Compliance-Message-Auth-Key";
    public const KDF_COMMIT_SALT = "FediE2EE-v1-Compliance-KDF-Salt";
    public const MEM_LIMIT = 16777216; // 16 MiB
    public const OPS_LIMIT = 3;

    /**
     * @throws SodiumException
     */
    public function getPlaintextCommitment(
        string $attributeName,
        string $plaintext,
        string $merkleRoot,
        string $salt
    ): string {
        $l = self::len($merkleRoot) . $merkleRoot .
            self::len($attributeName) . $attributeName .
            self::len($plaintext) . $plaintext;

        return sodium_crypto_pwhash(
            32,
            $l,
            $salt,
            self::OPS_LIMIT,
            self::MEM_LIMIT,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public function encryptAttribute(
        string $attributeName,
        string $plaintext,
        string $ikm,
        string $merkleRoot
    ): string {
        $h = self::VERSION;
        $r = random_bytes(32);

        $encInfo = self::KDF_ENCRYPT_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $encKeyNonce = hash_hkdf('sha512', $ikm, 56, $encInfo, '');
        $Ek = substr($encKeyNonce, 0, 32);
        $n = substr($encKeyNonce, 32, 24);

        $authInfo = self::KDF_AUTH_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $Ak = hash_hkdf('sha512', $ikm, 32, $authInfo, '');

        $saltInfo = self::KDF_COMMIT_SALT . $h . $r . self::len($merkleRoot) . $merkleRoot . self::len($attributeName) . $attributeName;
        $s = substr(hash('sha512', $saltInfo, true), 0, 16);

        $Q = $this->getPlaintextCommitment($attributeName, $plaintext, $merkleRoot, $s);
        $c = sodium_crypto_stream_xor($plaintext, $n, $Ek);
        $t = substr(
            hash_hmac(
                'sha512',
                $h . $r . self::len($attributeName) . $attributeName . self::len($c) . $c . self::len($Q) . $Q,
                $Ak,
                true
            ),
            0,
            32
        );

        return $h . $r . $Q . $t . $c;
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function decryptAttribute(
        string $attributeName,
        string $ciphertext,
        string $ikm,
        string $merkleRoot
    ): string {
        $h = substr($ciphertext, 0, 1);
        if (!hash_equals($h, self::VERSION)) {
            throw new CryptoException("Invalid version");
        }
        $r = substr($ciphertext, 1, 32);
        $Q = substr($ciphertext, 33, 32);
        $t = substr($ciphertext, 65, 32);
        $c = substr($ciphertext, 97);

        $authInfo = self::KDF_AUTH_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $Ak = hash_hkdf('sha512', $ikm, 32, $authInfo, '');

        $t2 = substr(
            hash_hmac(
                'sha512',
                $h . $r . self::len($attributeName) . $attributeName . self::len($c) . $c . self::len($Q) . $Q,
                $Ak,
                true
            ),
            0,
            32
        );

        if (!hash_equals($t, $t2)) {
            throw new CryptoException("Invalid authentication tag");
        }

        $encInfo = self::KDF_ENCRYPT_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $encKeyNonce = hash_hkdf('sha512', $ikm, 56, $encInfo, '');
        $Ek = substr($encKeyNonce, 0, 32);
        $n = substr($encKeyNonce, 32, 24);
        $p = sodium_crypto_stream_xor($c, $n, $Ek);

        $saltInfo = self::KDF_COMMIT_SALT . $h . $r . self::len($merkleRoot) . $merkleRoot . self::len($attributeName) . $attributeName;
        $s = substr(hash('sha512', $saltInfo, true), 0, 16);

        $Q2 = $this->getPlaintextCommitment($attributeName, $p, $merkleRoot, $s);

        if (!hash_equals($Q, $Q2)) {
            throw new CryptoException("Invalid plaintext commitment");
        }

        return $p;
    }

    public static function len(string $str): string
    {
        $len = strlen($str);
        return pack('P', $len);
    }
}
