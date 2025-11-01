<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Encoding;

use FediE2EE\PKD\Crypto\Encoding\Base58BtcVarTime;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Base58BtcVarTime::class)]
class Base58BtcVarTimeTest extends TestCase
{

    /**
     * Exhaustively test all inputs between 0 and 2^15 for division and modulo 58
     * @return void
     */
    public function testDiv58(): void
    {
        $this->markTestSkipped('test');
        for ($x = 0; $x < 32768; ++$x) {
            $expectedDiv = intdiv($x, 58);
            $expectedMod = $x % 58;
            [$div, $mod] = Base58BtcVarTime::div58($x);
            $this->assertSame($expectedDiv, $div, 'division (' . $x . ')');
            $this->assertSame($expectedMod, $mod, 'modulo (' . $x . ')');
        }
    }

    public static function vectorProvider(): array
    {
        return [
            ["\x01", '2'],
            ["\x3A", '21'],
            ["\x3B", '22'],
            ["\x08", '9'],
            ["\x09", 'A'],
            ["\x0A", 'B'],
            ["\x20", 'Z'],
            ["\x00\x00\x01\x02", '115T'],
            ["\x00\x00\x01\x02\x00\x03", '112VfFG'],
            ['Hello World!', '2NEpo7TZRRrLZSi2U'],
            ['The quick brown fox jumps over the lazy dog.', 'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z'],
            ["\x00\x00\x28\x7f\xb4\xcd", '11233QC4']
        ];
    }


    #[DataProvider("vectorProvider")]
    public function testVectors(string $input, string $expected): void
    {
        $encoded = Base58BtcVarTime::encode($input);
        $decoded = Base58BtcVarTime::decode($expected);
        $this->assertSame($expected, $encoded, 'encoding: ' . $input);
        $this->assertSame($input, $decoded, 'decoding: ' . $expected);
    }

    public function testEncodeDecodeByte(): void
    {
        $this->markTestSkipped('test');
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $input = range(0, 57);
        $str = '';
        $a = [];
        foreach ($input as $i) {
            $a[$i] = Base58BtcVarTime::encodeByte($i);
            $str .= pack('C', $a[$i]);
        }
        $this->assertSame($alphabet, $str);

        for ($i = 0; $i < 58; ++$i) {
            $this->assertSame($i, Base58BtcVarTime::decodeByte($a[$i]), 'index = '. $i);
        }
    }
    public function testEncodeDecode(): void
    {
        $this->markTestSkipped('test');
        for ($i = 1; $i < 100; ++$i) {
            $random = random_bytes($i);
            $encoded = Base58BtcVarTime::encode($random);
            $this->assertGreaterThanOrEqual($i, strlen($encoded));
            $decoded = Base58BtcVarTime::decode($encoded);
            $this->assertSame(Hex::encode($random), Hex::encode($decoded), 'encoding len = ' . $i);
            $this->assertSame($random, $decoded, 'encoding len = ' . $i);
        }
    }
}