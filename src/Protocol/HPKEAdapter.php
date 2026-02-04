<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\{
    DecapsKeyInterface,
    EncapsKeyInterface
};
use SensitiveParameter;
use function hash_equals, hash_hmac, preg_match, strlen, substr;

class HPKEAdapter
{
    public const HPKE_PREFIX = 'hpke:';
    public const DEFAULT_INFO = 'fedi-e2ee/public-key-directory:v1:protocol-message';
    public const KEY_ID_DOMAIN = 'fedi-e2ee/public-key-directory:v1:key-id';

    public function __construct(
        private readonly HPKE $hpke,
        public string         $info = self::DEFAULT_INFO,
    ) {}

    /**
     * Is this string an HPKE-encrypted ciphertext with the hpke: prefix?
     *
     * @api
     */
    public function isHpkeCiphertext(string $message): bool
    {
        if (strlen($message) < 5) {
            return false;
        }
        $header = substr($message, 0, 5);
        if (!hash_equals($header, self::HPKE_PREFIX)) {
            return false;
        }
        return preg_match('#^[A-Za-z0-9-_]+$#', substr($message, 5)) === 1;
    }

    /**
     * Decrypt the payload.
     *
     * @throws HPKEException
     */
    public function open(
        DecapsKeyInterface $decapsKey,
        EncapsKeyInterface $encapsKey,
        string $payload,
    ): string {
        if (strlen($payload) < 5) {
            throw new HPKEException('Invalid payload: too short');
        }
        $header = substr($payload, 0, 5);
        if (!hash_equals(self::HPKE_PREFIX, $header)) {
            throw new HPKEException('Invalid payload header');
        }
        $remainder = substr($payload, 5);
        if (!preg_match('#^[A-Za-z0-9-_]+$#', $remainder)) {
            throw new HPKEException('HPKE ciphertext must be base64url encoded without padding');
        }
        return $this->hpke->openBase(
            sk: $decapsKey,
            ciphertext: Base64UrlSafe::decodeNoPadding($remainder),
            aad: $this->keyId($encapsKey),
            info: $this->info,
        );
    }

    /**
     * Encrypt a message using the Encapsulation Key.
     *
     * @throws HPKEException
     */
    public function seal(
        EncapsKeyInterface $encapsKey,
        #[SensitiveParameter] string $plaintext,
    ): string {
        return self::HPKE_PREFIX . Base64UrlSafe::encodeUnpadded(
            $this->hpke->sealBase(
                pk: $encapsKey,
                plaintext: $plaintext,
                aad: $this->keyId($encapsKey),
                info: $this->info,
            )
        );
    }

    /**
     * Calculate the Key-ID deterministically from an HPKE Encapsulation Key and the configured hash function.
     *
     * @psalm-suppress NoInterfaceProperties
     */
    public function keyId(EncapsKeyInterface $encapsKey): string
    {
        $hashAlgo = $this->hpke->kdf->hash->value;
        $keyBytes = $encapsKey->bytes;
        return hash_hmac($hashAlgo, self::KEY_ID_DOMAIN, $keyBytes, true);
    }
}
