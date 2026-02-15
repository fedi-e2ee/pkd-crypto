<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Hex;
use SensitiveParameter;
use SodiumException;
use function chunk_split,
hash_equals,
is_string,
sodium_crypto_sign_detached,
sodium_crypto_sign_keypair,
sodium_crypto_sign_publickey_from_secretkey,
sodium_crypto_sign_secretkey,
sodium_crypto_sign_seed_keypair,
str_replace,
strlen,
substr;

/**
 * @api
 */
final class SecretKey
{
    use UtilTrait;
    private const PEM_PREFIX_ED25519 = '302e020100300506032b657004220420';
    private string $bytes;
    private string $algo;

    public function __construct(
        #[SensitiveParameter]
        string $bytes,
        string $algo = 'ed25519'
    ) {
        $expectedLength = match($algo) {
            'ed25519' => 64,
            default => throw new CryptoException('Unknown algorithm: ' . $algo)
        };
        if (strlen($bytes) !== $expectedLength) {
            throw new CryptoException('Secret key must be ' . $expectedLength . ' bytes');
        }
        $this->bytes = $bytes;
        $this->algo = $algo;
    }

    /**
     * Generate a random secret key.
     *
     * The default (and currently only supported) algorithm is Ed25519.
     *
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public static function generate(string $algo = 'ed25519'): self
    {
        // We're using a switch-case to make this extensible in the future
        switch ($algo) {
            case 'ed25519':
                $keypair = sodium_crypto_sign_keypair();
                $bytes = sodium_crypto_sign_secretkey($keypair);
                return new SecretKey($bytes, $algo);
            default:
                throw new NotImplementedException('');
        }
    }

    /**
     * Returns a PEM-encoded string representing the secret key.
     * Uses PKCS#8 format with only the 32-byte seed.
     */
    public function encodePem(): string
    {
        $seed = substr($this->bytes, 0, 32);
        $encoded = Base64::encode(
            Hex::decode(self::PEM_PREFIX_ED25519) . $seed
        );
        return "-----BEGIN PRIVATE KEY-----\n" .
            self::dos2unix(chunk_split($encoded, 64)).
            "-----END PRIVATE KEY-----";
    }

    /**
     * Load a secret key from a PEM-encoded string.
     *
     * @param string $pem
     * @param string $algo
     * @return self
     *
     * @throws CryptoException
     * @throws SodiumException
     */
    public static function importPem(string $pem, string $algo = 'ed25519'): SecretKey
    {
        if (!hash_equals('ed25519', $algo)) {
            throw new CryptoException('Only ed25519 keys are supported');
        }
        $formattedKey = str_replace('-----BEGIN PRIVATE KEY-----', '', $pem);
        $formattedKey = str_replace('-----END PRIVATE KEY-----', '', $formattedKey);
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
        $seed = substr($key, strlen($prefix));
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        return new SecretKey(
            sodium_crypto_sign_secretkey($keypair),
            $algo
        );
    }

    /**
     * Get the raw key bytes.
     *
     * @api
     */
    public function getBytes(): string
    {
        return $this->bytes;
    }

    /**
     * Get the secret key algorithm.
     *
     * @api
     */
    public function getAlgo(): string
    {
        return $this->algo;
    }

    /**
     * Get the public key that corresponds to this secret key.
     *
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function getPublicKey(): PublicKey
    {
        // We're using a switch-case to make this extensible in the future
        switch ($this->algo) {
            case 'ed25519':
                $pk = sodium_crypto_sign_publickey_from_secretkey($this->bytes);
                return new PublicKey($pk, $this->algo);
            default:
                throw new NotImplementedException('');
        }
    }

    /**
     * Calculate a revocation token from a secret key.
     */
    public function getRevocationToken(): string
    {
        return (new Revocation())->revokeThirdParty($this);
    }

    /**
     * Sign a message using the secret key.
     *
     * This is preferred over exporting the raw key bytes and using those bytes directly.
     *
     * @param string $message
     * @return string
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function sign(string $message): string
    {
        switch ($this->algo) {
            case 'ed25519':
                return sodium_crypto_sign_detached($message, $this->bytes);
            default:
                throw new NotImplementedException('');
        }
    }
}
