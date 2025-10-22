<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use ParagonIE\ConstantTime\Binary;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;
use SodiumException;

class EncryptedMessageTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testSignVerifyEncrypted(): void
    {
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $symKey = SymmetricKey::generate();

        $keyMap = new AttributeKeyMap();
        $keyMap->addKey('actor', $symKey);

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $encrypted = $addKey->encrypt($keyMap);

        $sm = new SignedMessage($encrypted, $recent);
        $signature = $sm->sign($sk);

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9-_]{86,88}$/', $signature);
        $decoded = Base64UrlSafe::decodeNoPadding($signature);
        $this->assertSame(64, Binary::safeStrlen($decoded));
        $this->assertTrue($sm->verify($pk));

        $decrypted = $encrypted->decrypt($keyMap);
        $this->assertInstanceOf(AddKey::class, $decrypted);
        $this->assertSame('https://example.com/@alice', $decrypted->getActor());
        $this->assertSame($pk->toString(), $decrypted->getPublicKey()->toString());
    }
}
