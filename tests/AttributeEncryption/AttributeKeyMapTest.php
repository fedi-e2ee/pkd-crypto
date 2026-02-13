<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\AttributeEncryption;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\SymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AttributeKeyMap::class)]
class AttributeKeyMapTest extends TestCase
{
    /**
     * @throws CryptoException
     */
    public function testAddKey(): void
    {
        $keyMap = new AttributeKeyMap();
        $blah = str_repeat("\xff", 32);
        $keyMap->addKey('foo', new SymmetricKey($blah));
        $this->assertTrue($keyMap->hasKey('foo'));
        $this->assertFalse($keyMap->hasKey('bar'));
        $this->assertSame(['foo'], $keyMap->getAttributes());
        $got = $keyMap->getKey('foo');
        $this->assertInstanceOf(SymmetricKey::class, $got);
        $this->assertSame($blah, $got->getBytes());

        $keyMap->addRandomKey('baz');
        $this->assertTrue($keyMap->hasKey('baz'));
        $baz = $keyMap->getKey('baz');
        $this->assertNotSame($blah, $baz->getBytes());
    }

    public function testIsEmpty(): void
    {
        $keyMap = new AttributeKeyMap();
        $this->assertTrue($keyMap->isEmpty());

        $keyMap->addRandomKey('test');
        $this->assertFalse($keyMap->isEmpty());
    }
}
