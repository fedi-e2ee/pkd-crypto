<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SensitiveParameter;
use SodiumException;

/**
 * @api
 */
final class PublicKey
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

    public function toString(): string
    {
        // "ed25519:" || base64url_encode(pk)
        return 'ed25519:' .  Base64UrlSafe::encodeUnpadded($this->bytes);
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
