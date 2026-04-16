<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    InvalidSignatureException,
    NotImplementedException
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use PHPUnit\Framework\Attributes\DataProvider;
use FediE2EE\PKD\Crypto\{
    Enums\SigningAlgorithm,
    Revocation,
    SecretKey
};
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(Revocation::class)]
class RevocationTest extends TestCase
{
    use ExtraneousDataProviderTrait;

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider('pkdAllowedSigningAlgorithmProvider')]
    public function testRevokeFlow(SigningAlgorithm $alg): void
    {
        $sk = SecretKey::generate($alg);
        $pk = $sk->getPublicKey();

        $sk2 = SecretKey::generate($alg);

        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);
        $this->assertTrue($revocation->verifyRevocationToken($token));

        $token2 = $revocation->revokeThirdParty($sk2);
        $this->assertTrue($revocation->verifyRevocationToken($token2));

        $this->expectException(CryptoException::class);
        $revocation->verifyRevocationToken($token2, $pk);
    }

    /**
     * @throws CryptoException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    #[DataProvider('pkdAllowedSigningAlgorithmProvider')]
    public function testRevokeVerifyInvalidSignature(SigningAlgorithm $alg): void
    {
        $sk = SecretKey::generate($alg);
        $pk = $sk->getPublicKey();

        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);
        $this->assertTrue($revocation->verifyRevocationToken($token, $pk, true));

        [, $signed, $signature] = $revocation->decode($token);
        $signature[0] = chr(ord($signature[0]) ^ 1);
        $badToken = Base64UrlSafe::encodeUnpadded($signed . $signature);
        $this->assertNotSame($badToken, $token);

        $this->assertFalse($revocation->verifyRevocationToken($badToken, $pk));

        // verifyThrow
        $this->expectException(InvalidSignatureException::class);
        $revocation->verifyRevocationToken($badToken, $pk, true);
    }
}
