<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use SensitiveParameter;
use SodiumException;

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

    public function getBytes(): string
    {
        return $this->bytes;
    }

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
}
