<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\Interfaces\DecapsKeyInterface;
use ParagonIE\HPKE\Interfaces\EncapsKeyInterface;
use SensitiveParameter;

class HPKEAdapter
{
    public const HPKE_PREFIX = 'hpke:';
    public const DEFAULT_INFO = 'fedi-e2ee/public-key-directory:v1:protocol-message';
    public const KEY_ID_DOMAIN = 'fedi-e2ee/public-key-directory:v1:';

    public function __construct(
        private readonly HPKE $hpke,
        public string         $info = self::DEFAULT_INFO,
    ) {}

    /**
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

    public function keyId(EncapsKeyInterface $encapsKey): string
    {
        return hash_hmac(
            $this->hpke->kdf->hash->value,
            self::KEY_ID_DOMAIN,
            $encapsKey->bytes,
            true
        );
    }
}
