<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SodiumException;
use function hash_equals, is_null, strlen, substr;

//= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revocation-tokens
//# A revocation token is a compact token that a user can issue at any time to revoke an existing public key.
class Revocation
{
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revocation-tokens
    //# `REVOCATION_CONSTANT` is a domain-separated constant for revoking an existing key.
    private const REVOKE_VERSION = 'FediPKD1';
    private const REVOKE_CONSTANT =
        "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE" .
        "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE" .
        'revoke-public-key';

    /**
     * Calculate a Third-Party revocation token for the given Secret Key.
     *
     * @throws CryptoException
     * @throws Exceptions\NotImplementedException
     * @throws SodiumException
     */
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty
    //# Since you need the secret key to generate the revocation token for a given public key
    public function revokeThirdParty(SecretKey $sk): string
    {
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revocation-tokens
        //# tmp := version || REVOCATION_CONSTANT || public_key
        $tmp = self::REVOKE_VERSION . self::REVOKE_CONSTANT . $sk->getPublicKey()->getBytes();

        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revocation-tokens
        //# revocation_token := base64url_encode(tmp || Sign(secret_key, tmp))
        return Base64UrlSafe::encodeUnpadded(
            $tmp .
            $sk->sign($tmp)
        );
    }

    /**
     * Decode a Revocation token into its constinuent pieces for verification.
     *
     * @throws CryptoException
     */
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

    /**
     * Verify a revocation token.
     *
     * @throws CryptoException
     * @throws Exceptions\NotImplementedException
     * @throws SodiumException
     *
     */
    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#revokekeythirdparty-validation-steps
    //# Validate signature for  `version || REVOCATION_CONSTANT || public_key`, using `public_key`.
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
