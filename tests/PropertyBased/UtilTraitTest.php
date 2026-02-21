<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\UtilTrait;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
class UtilTraitTest extends TestCase
{
    use UtilTrait;
    use TestTrait;
    use ErisPhpUnit12Trait {
        ErisPhpUnit12Trait::getTestCaseAnnotations insteadof TestTrait;
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->erisSetupCompat();
    }

    public function testConstantTimeSelect(): void
    {
        $this->limitTo(1000)->forAll(
            Generators::choose(1, 10000)
        )->then(function (int $len): void {
            $string1 = random_bytes($len);
            $string2 = random_bytes($len);
            $this->assertSame($string1, $this->constantTimeSelect(1, $string1, $string2));
            $this->assertSame($string2, $this->constantTimeSelect(0, $string1, $string2));
        });
    }

    public function testPreAuthEncode(): void
    {
        $this->limitTo(1000)->forAll(
            Generators::string(),
            Generators::string()
        )->then(function (string $string1, string $string2): void {
            if ($string1 !== $string2) {
                $this->assertNotSame(
                    $this->preAuthEncode([$string1]),
                    $this->preAuthEncode([$string2]),
                );

                $this->assertNotSame(
                    $this->preAuthEncode([$string1, $string2]),
                    $this->preAuthEncode([$string2, $string1]),
                );
            } else {
                $this->assertSame(
                    $this->preAuthEncode([$string1]),
                    $this->preAuthEncode([$string2]),
                );
            }
        });
    }
}
