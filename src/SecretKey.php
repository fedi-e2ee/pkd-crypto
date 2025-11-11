<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Hex;
use SensitiveParameter;
use SodiumException;

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
        $this->bytes = $bytes;
        $this->algo = $algo;
    }

    /**
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

    public function encodePem(): string
    {
        $encoded = Base64::encode(
            Hex::decode(self::PEM_PREFIX_ED25519) . $this->bytes
        );
        return "-----BEGIN EC PRIVATE KEY-----\n" .
            self::dos2unix(chunk_split($encoded, 64)).
            "-----END EC PRIVATE KEY-----";
    }

    /**
     * @param string $pem
     * @param string $algo
     * @return self
     *
     * @throws CryptoException
     */
    public static function importPem(string $pem, string $algo = 'ed25519'): SecretKey
    {
        if (!hash_equals('ed25519', $algo)) {
            throw new CryptoException('Only ed25519 keys are supported');
        }
        $formattedKey = str_replace('-----BEGIN EC PRIVATE KEY-----', '', $pem);
        $formattedKey = str_replace('-----END EC PRIVATE KEY-----', '', $formattedKey);
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
        return new SecretKey(substr($key, strlen($prefix)), $algo);
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

    /**
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

    public function getRevocationToken(): string
    {
        return (new Revocation())->revokeThirdParty($this);
    }

    /**
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
