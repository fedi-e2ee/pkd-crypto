<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Encoding\Multibase;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Hex;
use SensitiveParameter;
use SodiumException;

/**
 * @api
 */
final class PublicKey
{
    use UtilTrait;
    private const PEM_PREFIX_ED25519 = '302a300506032b6570032100';
    private const MB_PREFIX_ED25519 = "\xed\x01";
    private string $bytes;
    private string $algo;

    public function __construct(
        #[SensitiveParameter]
        string $bytes,
        string $algo = 'ed25519'
    ) {
        $this->bytes = $bytes;
        $this->algo = $algo;
    }

    public function encodePem(): string
    {
        $encoded = Base64::encode(
            Hex::decode(self::PEM_PREFIX_ED25519) . $this->bytes
        );
        return "-----BEGIN PUBLIC KEY-----\n" .
            self::dos2unix(chunk_split($encoded, 64)).
            "-----END PUBLIC KEY-----";
    }

    /**
     * @throws CryptoException
     * @throws EncodingException
     */
    public static function fromMultibase(string $encoded): PublicKey
    {
        $decoded = Multibase::decode($encoded);
        if (strlen($decoded) !== 34) {
            throw new CryptoException('Invalid public key');
        }
        $actualPrefix = substr($decoded, 0, 2);
        if (!hash_equals(self::MB_PREFIX_ED25519, $actualPrefix)) {
            throw new CryptoException('Incorrect public key type');
        }
        return new PublicKey(substr($decoded, 2));
    }

    public function toMultibase(bool $useUnsafe = false): string
    {
        return Multibase::encode(self::MB_PREFIX_ED25519 . $this->bytes, $useUnsafe);
    }

    /**
     * @param string $pem
     * @param string $algo
     * @return self
     *
     * @throws CryptoException
     */
    public static function importPem(string $pem, string $algo = 'ed25519'): PublicKey
    {
        if (!hash_equals('ed25519', $algo)) {
            throw new CryptoException('Only ed25519 keys are supported');
        }
        $formattedKey = str_replace('-----BEGIN PUBLIC KEY-----', '', $pem);
        $formattedKey = str_replace('-----END PUBLIC KEY-----', '', $formattedKey);
        /**
         * @psalm-suppress DocblockTypeContradiction
         * PHP 8.4 updated the docblock return for str_replace, which makes this check required
         */
        if (!is_string($formattedKey)) {
            throw new CryptoException('Invalid PEM format');
        }
        $formattedKey = self::stripNewlines($formattedKey);
        $key = Base64::decode($formattedKey);
        $prefix = Hex::decode(self::PEM_PREFIX_ED25519);
        if (!hash_equals(substr($key, 0, strlen($prefix)), $prefix)) {
            throw new CryptoException('Invalid PEM prefix');
        }
        return new PublicKey(substr($key, strlen($prefix)), $algo);
    }

    /**
     * @api
     */
    public function getBytes(): string
    {
        return $this->bytes;
    }

    /**
     * @api
     */
    public function getAlgo(): string
    {
        return $this->algo;
    }

    public function toString(): string
    {
        // "ed25519:" || base64url_encode(pk)
        return 'ed25519:' .  Base64UrlSafe::encodeUnpadded($this->bytes);
    }

    /**
     * @psalm-suppress UnusedVariable
     */
    public static function fromString(string $pk): self
    {
        [$algo, $bytes] = explode(':', $pk);
        return new self(Base64UrlSafe::decodeNoPadding($bytes), $algo);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * @param string $signature
     * @param string $message
     * @return bool
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function verify(string $signature, string $message): bool
    {
        switch ($this->algo) {
            case 'ed25519':
                return sodium_crypto_sign_verify_detached($signature, $message, $this->bytes);
            default:
                throw new NotImplementedException('');
        }
    }
}
