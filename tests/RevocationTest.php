<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    InvalidSignatureException,
    NotImplementedException};
use ParagonIE\ConstantTime\Base64UrlSafe;
use FediE2EE\PKD\Crypto\{
    Revocation,
    SecretKey
};
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(Revocation::class)]
class RevocationTest extends TestCase
{
    /**
     * @return void
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeFlow(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sk2 = SecretKey::generate();

        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);
        $this->assertTrue($revocation->verifyRevocationToken($token));

        $token2 = $revocation->revokeThirdParty($sk2);
        $this->assertTrue($revocation->verifyRevocationToken($token2));

        $this->expectException(CryptoException::class);
        $revocation->verifyRevocationToken($token2, $pk);
    }

    /**
     * @return void
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeVerifyInvalidSignature(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);
        $this->assertTrue($revocation->verifyRevocationToken($token, $pk));

        [, $signed, $signature] = $revocation->decode($token);
        $signature[0] = chr(ord($signature[0]) ^ 1);
        $badToken = Base64UrlSafe::encodeUnpadded($signed . $signature);

        $this->assertFalse($revocation->verifyRevocationToken($badToken, $pk));

        // verifyThrow
        $this->expectException(InvalidSignatureException::class);
        $revocation->verifyRevocationToken($badToken, $pk, true);
    }
}
