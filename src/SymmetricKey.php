<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use ParagonIE\ConstantTime\Binary;
use Random\RandomException;
use SensitiveParameter;
use SodiumException;
use function
    is_string,
    random_bytes,
    sodium_crypto_aead_xchacha20poly1305_ietf_decrypt,
    sodium_crypto_aead_xchacha20poly1305_ietf_encrypt,
    strlen;

class SymmetricKey
{
    private string $bytes;

    /**
     * @throws CryptoException
     */
    public function __construct(
        #[SensitiveParameter]
        string $bytes
    ){
        if (strlen($bytes) !== 32) {
            throw new CryptoException(
                'Symmetric key must be 32 bytes'
            );
        }
        $this->bytes = $bytes;
    }

    /**
     * Generate a random 256-bit secret key.
     */
    public static function generate(): self
    {
        return new self(random_bytes(32));
    }

    /**
     * Get the raw key bytes.
     */
    public function getBytes(): string
    {
        return $this->bytes;
    }

    /**
     * Encrypt some arbitrary plaintext message (and optional associated data) with this key.
     *
     * @throws SodiumException
     * @throws RandomException
     */
    public function encrypt(string $plaintext, string $ad = ''): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $ad,
            $nonce,
            $this->bytes
        );
        return $nonce . $ciphertext;
    }

    /**
     * Inverse of encrypt().
     *
     * @throws SodiumException
     */
    public function decrypt(string $ciphertext, string $ad = ''): string
    {
        $nonce = Binary::safeSubstr($ciphertext, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $encrypted = Binary::safeSubstr($ciphertext, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $encrypted,
            $ad,
            $nonce,
            $this->bytes
        );
        if (!is_string($plaintext)) {
            throw new SodiumException('Decryption failed');
        }
        return $plaintext;
    }
}
