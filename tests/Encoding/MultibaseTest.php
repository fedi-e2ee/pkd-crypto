<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Encoding;

use FediE2EE\PKD\Crypto\Encoding\Multibase;
use PHPUnit\Framework\TestCase;

class MultibaseTest extends TestCase
{
    public function testKnownInput(): void
    {
        $seed = sodium_crypto_generichash('Soatok is a gay nerd');

        $default = Multibase::encode($seed);
        $this->assertSame('uyIKiwR76sj5kwacP3UctmFyRE2Mp6MyTj23L2p6e1bY', $default);

        $base58 = Multibase::encode($seed, true);
        $this->assertSame('zEVi5KYwjxteew1h7x1CEoqh3VJGAYuqXaxkzGdvAMYmK', $base58);

        $this->assertSame(Multibase::decode($base58), Multibase::decode($default));
    }
}
