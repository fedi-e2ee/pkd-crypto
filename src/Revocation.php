<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use ParagonIE\ConstantTime\Base64UrlSafe;

//= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
//# RevokeKeyThirdParty: Emergency key revocation using a revocation token.
class Revocation
{
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
    //# The revocation token format is: "FediPKD1" || REVOCATION_CONSTANT || public_key || signature
    private const REVOKE_VERSION = 'FediPKD1';
    private const REVOKE_CONSTANT =
        "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE" .
        "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE" .
        'revoke-public-key';

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
    //# Generate a revocation token that proves possession of the secret key.
    public function revokeThirdParty(SecretKey $sk): string
    {
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
        //# tmp = "FediPKD1" || REVOCATION_CONSTANT || public_key
        $tmp = self::REVOKE_VERSION . self::REVOKE_CONSTANT . $sk->getPublicKey()->getBytes();

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
        //# revocation_token = base64url(tmp || Ed25519.Sign(secret_key, tmp))
        return Base64UrlSafe::encodeUnpadded(
            $tmp .
            $sk->sign($tmp)
        );
    }

    public function decode(string $token): array
    {
        $decoded = Base64UrlSafe::decodeNoPadding($token);
        $len = strlen($decoded);
        // 8 + 49 + 32 + 64
        if ($len < 153) {
            throw new CryptoException('Token is too short');
        }
        $header = substr($decoded, 0, 8);
        if (!hash_equals($header, self::REVOKE_VERSION)) {
            throw new CryptoException('Invalid revocation header');
        }
        $c = substr($decoded, 8, 49);
        if (!hash_equals(self::REVOKE_CONSTANT, $c)) {
            throw new CryptoException('Invalid revocation constant');
        }
        $pk = new PublicKey(substr($decoded, 57, 32));
        $signature = substr($decoded, 89, SODIUM_CRYPTO_SIGN_BYTES);
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new CryptoException('error extracting signature');
        }
        $signed = substr($decoded, 0, 89);
        return [$pk, $signed, $signature];
    }

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
    //# Verify the signature on the revocation token to prove secret key possession.
    public function verifyRevocationToken(string $token, ?PublicKey $pk = null): bool
    {
        /** @var PublicKey $pkPrime */
        [$pkPrime, $tmp, $signature] = $this->decode($token);
        if (!is_null($pk)) {
            if (!hash_equals($pkPrime->toString(), $pk->toString())) {
                throw new CryptoException('mismatched public key');
            }
        }
        return $pkPrime->verify($signature, $tmp);
    }
}
