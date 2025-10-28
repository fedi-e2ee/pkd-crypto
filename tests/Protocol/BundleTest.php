<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

class BundleTest extends TestCase
{
    public function testToSignedMessage()
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $signed = new SignedMessage($addKey, $recent);
        $signature = $signed->sign($sk);

        $bundle = new Bundle(
            $addKey->getAction(),
            $addKey->jsonSerialize(),
            $recent,
            Base64UrlSafe::decodeNoPadding($signature),
            new AttributeKeyMap()
        );

        $signedFromBundle = $bundle->toSignedMessage();
        $this->assertTrue($signedFromBundle->verify($pk));
    }
}
