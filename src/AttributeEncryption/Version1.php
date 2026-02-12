<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\AttributeEncryption;

use Exception;
use FediE2EE\PKD\Crypto\SymmetricKey;
use FediE2EE\PKD\Crypto\UtilTrait;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use SodiumException;
use Override;
use function
    hash,
    hash_equals,
    hash_hkdf,
    hash_hmac,
    openssl_decrypt,
    openssl_encrypt,
    pack,
    random_bytes,
    sodium_crypto_pwhash,
    strlen,
    substr;

//= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-shreddability
//# using a committing authenticated encryption mode.
/**
 * @api
 */
class Version1 implements AttributeVersionInterface
{
    use UtilTrait;

    public const VERSION = "\x01";
    public const KDF_ENCRYPT_KEY = "FediE2EE-v1-Compliance-Encryption-Key";
    public const KDF_AUTH_KEY = "FediE2EE-v1-Compliance-Message-Auth-Key";
    public const KDF_COMMIT_SALT = "FediE2EE-v1-Compliance-KDF-Salt";
    public const MEM_LIMIT = 16777216; // 16 MiB
    public const OPS_LIMIT = 3;

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
    //# Calculate a commitment of the plaintext
    /**
     * @throws SodiumException
     */
    #[Override]
    public function getPlaintextCommitment(
        string $attributeName,
        string $plaintext,
        string $merkleRoot,
        string $salt
    ): string {
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-plaintext-commitment-algorithm
        //# Set `l` to `len(m) || m || len(a) || a || len(p) || p`.
        $l = self::len($merkleRoot) . $merkleRoot .
            self::len($attributeName) . $attributeName .
            self::len($plaintext) . $plaintext;

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-plaintext-commitment-algorithm
        //# Set `Q` to the output of [`PwKDF`](#version-1-functions)
        return sodium_crypto_pwhash(
            32,
            $l,
            $salt,
            self::OPS_LIMIT,
            self::MEM_LIMIT,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
    //# Encrypt the plaintext attribute using [`Stream`](#version-1-functions), with the nonce set to `n`, to obtain the
    /**
     * @throws SodiumException
     * @throws Exception
     */
    #[Override]
    public function encryptAttribute(
        string $attributeName,
        string $plaintext,
        SymmetricKey $ikm,
        string $merkleRoot
    ): string {
        $h = self::VERSION;
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# Generate 32 bytes of random data, `r`.
        $r = random_bytes(32);

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# Derive an encryption key, `Ek`, and nonce, `n`, through [`KDF`](#version-1-functions)
        $encInfo = self::KDF_ENCRYPT_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $encKeyNonce = hash_hkdf('sha512', $ikm->getBytes(), 48, $encInfo, '');
        $Ek = substr($encKeyNonce, 0, 32);
        $n = substr($encKeyNonce, 32, 16);

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# Derive an authentication key, `Ak`, through [`KDF`](#version-1-functions)
        $authInfo = self::KDF_AUTH_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $Ak = hash_hkdf('sha512', $ikm->getBytes(), 32, $authInfo, '');

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# Derive a commitment salt, `s`, as the [`Hash`](#version-1-functions)
        $saltInfo = self::KDF_COMMIT_SALT . $h . $r . self::len($merkleRoot) . $merkleRoot . self::len($attributeName) . $attributeName;
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# truncated to 128 bits (big endian / the least significant bits).
        $s = substr(hash('sha512', $saltInfo, true), 48, 16);

        $Q = $this->getPlaintextCommitment($attributeName, $plaintext, $merkleRoot, $s);
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# ciphertext, `c`.
        $c = openssl_encrypt($plaintext, 'aes-256-ctr', $Ek, OPENSSL_RAW_DATA, $n);

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# Truncate the HMAC output to the rightmost 32 bytes (256 bits)
        $t = substr(
            hash_hmac(
                'sha512',
                $h . $r . self::len($attributeName) . $attributeName . self::len($c) . $c . self::len($Q) . $Q,
                $Ak,
                true
            ),
            32,
            32
        );

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-encryption-algorithm
        //# Return `h || r || Q || t || c`.
        return $h . $r . $Q . $t . $c;
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[Override]
    public function decryptAttribute(
        string $attributeName,
        string $ciphertext,
        SymmetricKey $ikm,
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
        $Ak = hash_hkdf('sha512', $ikm->getBytes(), 32, $authInfo, '');

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-decryption-algorithm
        //# Truncate the HMAC output to the rightmost 32 bytes (256 bits)
        $t2 = substr(
            hash_hmac(
                'sha512',
                $h . $r . self::len($attributeName) . $attributeName . self::len($c) . $c . self::len($Q) . $Q,
                $Ak,
                true
            ),
            32,
            32
        );

        if (!hash_equals($t, $t2)) {
            throw new CryptoException("Invalid authentication tag");
        }

        $encInfo = self::KDF_ENCRYPT_KEY . $h . $r . self::len($attributeName) . $attributeName;
        $encKeyNonce = hash_hkdf('sha512', $ikm->getBytes(), 48, $encInfo, '');
        $Ek = substr($encKeyNonce, 0, 32);
        $n = substr($encKeyNonce, 32, 16);
        $p = openssl_decrypt($c, 'aes-256-ctr', $Ek, OPENSSL_RAW_DATA, $n);

        $saltInfo = self::KDF_COMMIT_SALT . $h . $r . self::len($merkleRoot) . $merkleRoot . self::len($attributeName) . $attributeName;
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#message-attribute-decryption-algorithm
        //# truncated to 128 bits (big endian / the least significant bits).
        $s = substr(hash('sha512', $saltInfo, true), 48, 16);

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
