<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\UtilTrait;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
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
}
