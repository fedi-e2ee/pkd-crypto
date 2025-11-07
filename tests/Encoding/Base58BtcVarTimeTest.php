<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Encoding;

use FediE2EE\PKD\Crypto\Encoding\Base58BtcVarTime;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
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
            ["\x00\x00\x00\x00\x28\x7f\xb4\xcd", '1111233QC4'],
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
        for ($i = 1; $i < 100; ++$i) {
            $random = random_bytes($i);
            $encoded = Base58BtcVarTime::encode($random);
            $this->assertGreaterThanOrEqual($i, strlen($encoded));
            $decoded = Base58BtcVarTime::decode($encoded);
            $this->assertSame(Hex::encode($random), Hex::encode($decoded), 'encoding len = ' . $i);
            $this->assertSame($random, $decoded, 'encoding len = ' . $i);
        }
    }

    public static function byteProvider(): array
    {
        $dummy = [];
        // exhaustively test all 256 possibilities with dummy values:
        for ($i = 0; $i < 48; ++$i) {
            $dummy[] = [0, $i, false];
        }
        for ($i = 123; $i < 256; ++$i) {
            $dummy[] = [0, $i, false];
        }

        // these are the only interesting cases:
        return [
            [0, 0x30, false],
            // 0 - 8 -> '1' - '9;
            [0, 0x31, true], [1, 0x32, true], [2, 0x33, true],
            [3, 0x34, true], [4, 0x35, true], [5, 0x36, true],
            [6, 0x37, true], [7, 0x38, true], [8, 0x39, true],
            // 9 - 16
            [9, 0x41, true],  [10, 0x42, true], [11, 0x43, true], [12, 0x44, true],
            [13, 0x45, true], [14, 0x46, true], [15, 0x47, true], [16, 0x48, true],
            // invalid char: "I"
            [0, 0x49, false],
            // 17 - 21
            [17, 0x4A, true], [18, 0x4B, true], [19, 0x4C, true],  [20, 0x4D, true],  [21, 0x4E, true],
            // invalid char: "O"
            [0, 0x4F, false],
            // 22 - 32
            [22, 0x50, true], [23, 0x51, true], [24, 0x52, true], [25, 0x53, true], [26, 0x54, true], [27, 0x55, true],
            [28, 0x56, true], [29, 0x57, true], [30, 0x58, true], [31, 0x59, true], [32, 0x5A, true],
            // invalid chars:
            [0, 0x5B, false], [0, 0x5C, false], [0, 0x5D, false], [0, 0x5E, false], [0, 0x5F, false], [0, 0x60, false],
            // 33 - 43
            [33, 0x61, true], [34, 0x62, true], [35, 0x63, true], [36, 0x64, true], [37, 0x65, true], [38, 0x66, true],
            [39, 0x67, true], [40, 0x68, true], [41, 0x69, true], [42, 0x6A, true], [43, 0x6B, true],
            // invalid char: "l"
            [0, 0x6C, false],
            // 44 - 57
            [44, 0x6D, true], [45, 0x6E, true], [46, 0x6F, true], [47, 0x70, true], [48, 0x71, true], [49, 0x72, true],
            [50, 0x73, true], [51, 0x74, true], [52, 0x75, true], [53, 0x76, true], [54, 0x77, true], [55, 0x78, true],
            [56, 0x79, true], [57, 0x7A, true],
            // invalid chars:
            [0, 0x7B, false],
        ] + $dummy;
    }

    #[DataProvider("byteProvider")]
    public function testByteCodec(int $b256, int $b58, bool $shouldSucceed): void
    {
        if ($shouldSucceed) {
            $encoded = Base58BtcVarTime::encodeByte($b256);
            $decoded = Base58BtcVarTime::decodeByte($b58);
            $this->assertSame($encoded, $b58, 'encoding');
            $this->assertSame($decoded, $b256, 'decoding');
        } else {
            $this->assertSame(-1, Base58BtcVarTime::decodeByte($b58));
        }
    }
}
