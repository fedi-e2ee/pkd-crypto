<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use Override;
use SodiumException;
use function
    is_string,
    random_bytes,
    sodium_crypto_aead_xchacha20poly1305_ietf_decrypt,
    sodium_crypto_aead_xchacha20poly1305_ietf_encrypt;

class SymmetricKey implements \JsonSerializable
{
    private string $bytes;

    public function __construct(
        #[\SensitiveParameter]
        string $bytes
    ){
        $this->bytes= $bytes;
    }

    public static function generate(): self
    {
        return new self(random_bytes(32));
    }

    public function getBytes(): string
    {
        return $this->bytes;
    }

    /**
     * @throws SodiumException
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

    /**
     * Please take care not to dump the string to an unauthorized user:
     *
     * @return string
     */
    #[Override]
    public function jsonSerialize(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->bytes);
    }
}
