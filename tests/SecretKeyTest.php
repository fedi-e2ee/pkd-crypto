<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\PublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use FediE2EE\PKD\Crypto\SecretKey;

#[CoversClass(SecretKey::class)]
class SecretKeyTest extends TestCase
{
    public function testGetPublicKey(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit test case for fedi-e2ee/pkd-client')
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

        $sk = new SecretKey($secret);
        $pk = $sk->getPublicKey();

        $this->assertInstanceOf(PublicKey::class, $pk);
        $this->assertSame($public, $pk->getBytes());
    }
}