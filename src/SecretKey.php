<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use SensitiveParameter;
use SodiumException;

/**
 * @api
 */
final class SecretKey
{
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
