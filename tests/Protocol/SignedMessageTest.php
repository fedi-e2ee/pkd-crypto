<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

class SignedMessageTest extends TestCase
{
    public function testSignVerify(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sm = new SignedMessage(
            new AddKey('https://example.com/@alice', $pk),
            $recent
        );
        $signature = $sm->sign($sk);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9-_]{86,88}$/', $signature);
        $decoded = Base64UrlSafe::decodeNoPadding($signature);
        $this->assertSame(64, mb_strlen($decoded, '8bit'));
        $this->assertTrue($sm->verify($pk));
    }

    public function testWithEncryption(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $map = (new AttributeKeyMap())
            ->addKey('actor', SymmetricKey::generate())
            ->addKey('public-key', SymmetricKey::generate());

        // Plaintext vs encrypted
        $plaintext = new AddKey('https://example.com/@alice', $pk);
        $encrypted = $plaintext->encrypt($map);

        $sm1 = new SignedMessage(
            $plaintext,
            $recent
        );
        $sm2 = new SignedMessage(
            $encrypted,
            $recent
        );
        $this->assertNotSame($sm1->jsonSerialize(), $sm2->jsonSerialize());
        // TODO better test
    }
}
