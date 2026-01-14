<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\UtilTrait;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @covers UtilTrait
 */
#[CoversTrait(UtilTrait::class)]
class UtilTraitTest extends TestCase
{
    use UtilTrait;

    public static function ctSelectProvider(): array
    {
        return [
            ['a', 'b'],
            ['abc', 'def'],
            ['a', ''],
        ];
    }

    /**
     * @dataProvider ctSelectProvider
     */
    #[DataProvider("ctSelectProvider")]
    public function testConstantTimeSelect(string $left, string $right): void
    {
        if (strlen($left) !== strlen($right)) {
            $this->expectException(CryptoException::class);
        }
        $this->assertSame($this->constantTimeSelect(1, $left, $right), $left);
        $this->assertSame($this->constantTimeSelect(0, $left, $right), $right);
    }

    public function testAllArrayKeysExist(): void
    {
        $target = ['a' => 1, 'b' => 2, 'c' => 3];

        // All keys exist
        $this->assertTrue(self::allArrayKeysExist($target, 'a', 'b', 'c'));
        $this->assertTrue(self::allArrayKeysExist($target, 'a', 'b'));
        $this->assertTrue(self::allArrayKeysExist($target, 'a'));

        // Some keys don't exist
        $this->assertFalse(self::allArrayKeysExist($target, 'a', 'd'));
        $this->assertFalse(self::allArrayKeysExist($target, 'd'));

        // Empty keys always true
        $this->assertTrue(self::allArrayKeysExist($target));

        // Empty target
        $this->assertFalse(self::allArrayKeysExist([], 'a'));
    }

    public function testAssertAllArrayKeysExistSuccess(): void
    {
        $target = ['a' => 1, 'b' => 2];
        self::assertAllArrayKeysExist($target, 'a', 'b');
        $this->assertTrue(true); // If we get here, no exception was thrown
    }

    public function testAssertAllArrayKeysExistFailure(): void
    {
        $target = ['a' => 1, 'b' => 2];
        $this->expectException(InputException::class);
        self::assertAllArrayKeysExist($target, 'a', 'c');
    }

    public function testAllArrayKeysExistPartialMissing(): void
    {
        $target = ['a' => 1, 'b' => 2];

        // First key exists, second doesn't
        $this->assertFalse(self::allArrayKeysExist($target, 'a', 'missing'));

        // First key doesn't exist, second does
        $this->assertFalse(self::allArrayKeysExist($target, 'missing', 'a'));
    }

    public function testPublicApiAccessibility(): void
    {
        $helper = new class {
            use UtilTrait;
        };

        // Test dos2unix is publicly accessible
        $this->assertSame("line1\nline2", $helper::dos2unix("line1\r\nline2"));

        // Test preAuthEncode is publicly accessible
        $encoded = $helper::preAuthEncode(['test']);
        $this->assertIsString($encoded);

        // Test LE64 is publicly accessible
        $packed = $helper::LE64(42);
        $this->assertSame(8, strlen($packed));

        // Test allArrayKeysExist is publicly accessible
        $this->assertTrue($helper::allArrayKeysExist(['a' => 1], 'a'));

        // Test assertAllArrayKeysExist is publicly accessible
        $helper::assertAllArrayKeysExist(['a' => 1], 'a');

        // Test constantTimeSelect is publicly accessible
        $this->assertSame('left', $helper->constantTimeSelect(1, 'left', 'rght'));

        // Test stringToByteArray is publicly accessible
        $this->assertSame([116, 101, 115, 116], $helper->stringToByteArray('test'));

        // Test stripNewLines is publicly accessible
        $this->assertSame("line1line2", $helper::stripNewlines("line1\r\nline2"));
    }

    public static function stripNewlinesProvider(): array
    {
        return [
            // [input, expected]
            ['', ''],
            ['no newlines', 'no newlines'],
            ["unix\nstyle", 'unixstyle'],
            ["windows\r\nstyle", 'windowsstyle'],
            ["mac\rstyle", 'macstyle'],
            ["\n", ''],
            ["\r", ''],
            ["\r\n", ''],
            ["\n\n\n", ''],
            ["\r\r\r", ''],
            ["a\nb\nc", 'abc'],
            ["a\rb\rc", 'abc'],
            ["\nabc", 'abc'],
            ["abc\n", 'abc'],
            ["\nabc\n", 'abc'],
            // Mixed newlines
            ["a\n\r\nb\r\nc", 'abc'],
            // All newlines
            ["\n\r\n\r", ''],
            // Adjacent newlines
            ["test\n\ndata", 'testdata'],
            ["test\r\rdata", 'testdata'],
            // Only CR characters (0x0d)
            ["\x0d\x0d\x0d", ''],
            // Only LF characters (0x0a)
            ["\x0a\x0a\x0a", ''],
            // Mixed content with various characters
            ["abc\x0adef\x0dghi", 'abcdefghi'],
            // Binary-safe: check non-newline control chars are preserved
            ["a\x09b", "a\x09b"],
            ["a\x00b", "a\x00b"],
        ];
    }

    #[DataProvider("stripNewlinesProvider")]
    public function testStripNewlines(string $input, string $expected): void
    {
        $this->assertSame($expected, self::stripNewlines($input));
    }

    public function testStripNewlinesPreservesLength(): void
    {
        // Input with known newline count should have predictable output length
        $input = "abc\ndef\rghi\r\njkl";
        $result = self::stripNewlines($input);
        // 12 chars minus 4 newline chars (one \n, one \r, one \r\n = 2)
        $this->assertSame('abcdefghijkl', $result);
        $this->assertSame(12, strlen($result));
    }

    public function testStripNewlinesOnlyRemovesCrLf(): void
    {
        // Verify that ONLY CR (0x0d) and LF (0x0a) are removed
        // Other characters in the vicinity should be preserved
        $input = "\x09\x0a\x0b\x0c\x0d\x0e";
        $expected = "\x09\x0b\x0c\x0e";
        $this->assertSame($expected, self::stripNewlines($input));
    }
}
