<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Encoding;

use FediE2EE\PKD\Crypto\Encoding\Base58BtcVarTime;
use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use Random\RandomException;

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
            ["\x00\x00\x00\x00\x00\x00\x00\x00", '11111111'],
            [str_repeat("\x00", 256), str_repeat('1', 256)],
            [str_repeat("\x00", 2048), str_repeat('1', 2048)],
            [str_repeat("\x00", 16384), str_repeat('1', 16384)],
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

    /**
     * @throws EncodingException
     */
    #[DataProvider("vectorProvider")]
    public function testVectors(string $input, string $expected): void
    {
        $encoded = Base58BtcVarTime::encode($input);
        $decoded = Base58BtcVarTime::decode($expected);
        $this->assertSame($expected, $encoded, 'encoding ' . strlen($input) . ': ' . $input);
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

    /**
     * @throws EncodingException
     * @throws RandomException
     */
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

    /**
     * Test empty string encoding returns empty string
     */
    public function testEncodeEmptyString(): void
    {
        $this->assertSame('', Base58BtcVarTime::encode(''));
    }

    /**
     * Test empty string decoding returns empty string
     */
    public function testDecodeEmptyString(): void
    {
        $this->assertSame('', Base58BtcVarTime::decode(''));
    }

    /**
     * Test boundary values around character thresholds
     */
    public function testCharacterBoundaries(): void
    {
        // Test values at boundaries where bit shifts matter
        // Value 8: boundary between '9' and 'A'
        $this->assertSame(0x39, Base58BtcVarTime::encodeByte(8)); // '9'
        $this->assertSame(0x41, Base58BtcVarTime::encodeByte(9)); // 'A'

        // Value 16: boundary in A-H range
        $this->assertSame(0x48, Base58BtcVarTime::encodeByte(16)); // 'H'
        $this->assertSame(0x4A, Base58BtcVarTime::encodeByte(17)); // 'J' (skips I)

        // Value 21: boundary in J-N range
        $this->assertSame(0x4E, Base58BtcVarTime::encodeByte(21)); // 'N'
        $this->assertSame(0x50, Base58BtcVarTime::encodeByte(22)); // 'P' (skips O)

        // Value 32: boundary in P-Z range
        $this->assertSame(0x5A, Base58BtcVarTime::encodeByte(32)); // 'Z'
        $this->assertSame(0x61, Base58BtcVarTime::encodeByte(33)); // 'a'

        // Value 43: boundary in a-k range
        $this->assertSame(0x6B, Base58BtcVarTime::encodeByte(43)); // 'k'
        $this->assertSame(0x6D, Base58BtcVarTime::encodeByte(44)); // 'm' (skips l)

        // Value 57: last valid value
        $this->assertSame(0x7A, Base58BtcVarTime::encodeByte(57)); // 'z'
    }

    /**
     * Test decode of each boundary character
     */
    public function testDecodeBoundaryCharacters(): void
    {
        // Decode boundary characters
        $this->assertSame(0, Base58BtcVarTime::decodeByte(0x31));  // '1' -> 0
        $this->assertSame(8, Base58BtcVarTime::decodeByte(0x39));  // '9' -> 8
        $this->assertSame(9, Base58BtcVarTime::decodeByte(0x41));  // 'A' -> 9
        $this->assertSame(16, Base58BtcVarTime::decodeByte(0x48)); // 'H' -> 16
        $this->assertSame(17, Base58BtcVarTime::decodeByte(0x4A)); // 'J' -> 17
        $this->assertSame(21, Base58BtcVarTime::decodeByte(0x4E)); // 'N' -> 21
        $this->assertSame(22, Base58BtcVarTime::decodeByte(0x50)); // 'P' -> 22
        $this->assertSame(32, Base58BtcVarTime::decodeByte(0x5A)); // 'Z' -> 32
        $this->assertSame(33, Base58BtcVarTime::decodeByte(0x61)); // 'a' -> 33
        $this->assertSame(43, Base58BtcVarTime::decodeByte(0x6B)); // 'k' -> 43
        $this->assertSame(44, Base58BtcVarTime::decodeByte(0x6D)); // 'm' -> 44
        $this->assertSame(57, Base58BtcVarTime::decodeByte(0x7A)); // 'z' -> 57

        // Invalid characters
        $this->assertSame(-1, Base58BtcVarTime::decodeByte(0x30)); // '0' invalid
        $this->assertSame(-1, Base58BtcVarTime::decodeByte(0x49)); // 'I' invalid
        $this->assertSame(-1, Base58BtcVarTime::decodeByte(0x4F)); // 'O' invalid
        $this->assertSame(-1, Base58BtcVarTime::decodeByte(0x6C)); // 'l' invalid

        for ($i = 0; $i < 0x31; $i++) {
            $this->assertSame(-1, Base58BtcVarTime::decodeByte($i));
        }
        // Simply not in the range at all:
        for ($i = 0x7B; $i < 0xFF; $i++) {
            $this->assertSame(-1, Base58BtcVarTime::decodeByte($i));
        }
    }

    /**
     * Test strings with leading zeros
     */
    public function testLeadingZeros(): void
    {
        // Leading null bytes should be preserved
        $input = "\x00\x00\x00\x01";
        $encoded = Base58BtcVarTime::encode($input);
        $decoded = Base58BtcVarTime::decode($encoded);
        $this->assertSame($input, $decoded);

        // All zeros
        $zeros = str_repeat("\x00", 10);
        $encodedZeros = Base58BtcVarTime::encode($zeros);
        $this->assertSame(str_repeat('1', 10), $encodedZeros);
        $decodedZeros = Base58BtcVarTime::decode($encodedZeros);
        $this->assertSame($zeros, $decodedZeros);
    }

    /**
     * Test large values to exercise carry and overflow handling
     */
    public function testLargeValues(): void
    {
        // Maximum byte value
        $maxByte = "\xff";
        $this->assertSame('5Q', Base58BtcVarTime::encode($maxByte));
        $this->assertSame($maxByte, Base58BtcVarTime::decode('5Q'));

        // Two max bytes
        $twoMax = "\xff\xff";
        $encoded = Base58BtcVarTime::encode($twoMax);
        $decoded = Base58BtcVarTime::decode($encoded);
        $this->assertSame($twoMax, $decoded);

        // Large random value
        $large = str_repeat("\xff", 32);
        $encoded = Base58BtcVarTime::encode($large);
        $decoded = Base58BtcVarTime::decode($encoded);
        $this->assertSame($large, $decoded);
    }

    /**
     * Test mixed zeros and non-zeros
     */
    public function testMixedZerosAndData(): void
    {
        // Zero at start
        $this->assertSame("\x00\x01", Base58BtcVarTime::decode('12'));

        // Zero at end (should be in the binary)
        $input = "\x01\x00";
        $encoded = Base58BtcVarTime::encode($input);
        $decoded = Base58BtcVarTime::decode($encoded);
        $this->assertSame($input, $decoded);

        // Zeros interspersed
        $input2 = "\x00\x01\x00\x02\x00";
        $encoded2 = Base58BtcVarTime::encode($input2);
        $decoded2 = Base58BtcVarTime::decode($encoded2);
        $this->assertSame($input2, $decoded2);
    }

    /**
     * Test that invalid characters return -1 consistently from decodeByte()
     */
    public function testInvalidDecodeCharacters(): void
    {
        // Characters just outside valid ranges
        for ($i = 0; $i < 0x31; ++$i) {
            $this->assertSame(-1, Base58BtcVarTime::decodeByte($i), "Byte $i should be invalid");
        }

        // Characters after 'z'
        for ($i = 0x7B; $i < 256; ++$i) {
            $this->assertSame(-1, Base58BtcVarTime::decodeByte($i), "Byte $i should be invalid");
        }
    }

    /**
     * Test div58 with edge cases
     */
    public function testDiv58EdgeCases(): void
    {
        // Zero
        [$div, $mod] = Base58BtcVarTime::div58(0);
        $this->assertSame(0, $div);
        $this->assertSame(0, $mod);

        // Exactly 58
        [$div, $mod] = Base58BtcVarTime::div58(58);
        $this->assertSame(1, $div);
        $this->assertSame(0, $mod);

        // Just under 58
        [$div, $mod] = Base58BtcVarTime::div58(57);
        $this->assertSame(0, $div);
        $this->assertSame(57, $mod);

        // Large value
        [$div, $mod] = Base58BtcVarTime::div58(32767);
        $this->assertSame(intdiv(32767, 58), $div);
        $this->assertSame(32767 % 58, $mod);
    }

    /**
     * Test single byte encoding/decoding for all values 0-255
     *
     * Also tests repeating the same byte value up to 5 times
     *
     * We go up to 5 because (4 * 58 < 255) but (5 * 58 > 255)
     */
    public function testAllSingleByteValues(): void
    {
        for ($i = 0; $i < 256; ++$i) {
            $input = chr($i);
            $encoded = Base58BtcVarTime::encode($input);
            $decoded = Base58BtcVarTime::decode($encoded);
            $this->assertSame($input, $decoded, "Failed for byte value $i");

            // Let's also try up to 5 repeats
            $concat = $input;
            for ($j = 0; $j < 5; ++$j) {
                $concat .= $input;
                $encoded = Base58BtcVarTime::encode($concat);
                $decoded = Base58BtcVarTime::decode($encoded);
                $this->assertSame($concat, $decoded, "Failed for byte value $i concatenation loop {$j}");
            }
        }
    }

    /**
     * This is just a provider for some inputs that should hit the boundary conditions
     * within the base58 codec, which should in turn fail if the codecs are mutated.
     */
    public static function pedanticEncodingProvider(): array
    {
        return [
            ['', ''],
            ["\x00", '1'],
            ["\x00\x00\x00\x00\x00", '11111'],
            ["\x01", '2'],
            ["\x02", '3'],
            ["\x03", '4'],
            ["\x04\x04", 'Jj'],
            ["\x05\x05\x05", '2gnp'],
            ["\x01\x02\x03\x04", '2VfUX'],
            ["\xFE", '5P'],
            ["\xFF", '5Q'],
            ["\xFF\xFF", 'LUv'],
            ["\x36\x36\x36\x36\x36", '77k5N45'],
            ["\x5C\x5C\x5C\x5C\x5C\x5C", 'nzbMxVxX'],
            ["\x00\x5D\x00", '185V'],
            ["\x00\x5D\x00\x00", '1YEnb'],
            ["\x12\x34\x56\x78\x9a\xbc\xde\xf0", '43c9JGph3DZ'],
            ["\xfe\xdc\xba\x98\x76\x54\x32\x10", 'jdV1ApWfY6s'],
        ];
    }

    #[DataProvider("pedanticEncodingProvider")]
    public function testPedanticEncoding(string $input, string $expected): void
    {
        $encoded = Base58BtcVarTime::encode($input);
        $this->assertSame($expected, $encoded);
        $this->assertSame($input, Base58BtcVarTime::decode($encoded));
    }
}
