<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\BundleException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class BundleTest extends TestCase
{
    public function testToSignedMessage()
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $this->assertIsString($addKey->toString());
        $signed = new SignedMessage($addKey, $recent);
        $signature = $signed->sign($sk);

        $bundle = new Bundle(
            $addKey->getAction(),
            $addKey->jsonSerialize(),
            $recent,
            $signature,
            new AttributeKeyMap()
        );

        $signedFromBundle = $bundle->toSignedMessage();
        $this->assertTrue($signedFromBundle->verify($pk));
    }

    public static function invalidFromFuzzer(): array
    {
       return [
           [sodium_hex2bin('18181818182d2d302d2d2d2d2d2d7e50f3')],
       ];
    }

    #[DataProvider("invalidFromFuzzer")]
    public function testInvalidInput(string $input): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson($input);
    }
}
