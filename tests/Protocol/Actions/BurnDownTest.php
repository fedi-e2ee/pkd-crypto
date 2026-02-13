<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol\Actions;

use DateTimeImmutable;
use FediE2EE\PKD\Crypto\Exceptions\{
    InputException,
    JsonException,
    NetworkException
};
use FediE2EE\PKD\Crypto\Protocol\Actions\BurnDown;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(BurnDown::class)]
class BurnDownTest extends TestCase
{
    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function testToArrayWithNullOtpExcludesOtpKey(): void
    {
        $burnDown = new BurnDown(
            'https://example.com/@alice',
            'operator@example.com',
            new DateTimeImmutable('2024-01-01T00:00:00Z'),
            null
        );

        $array = $burnDown->toArray();

        $this->assertArrayHasKey('actor', $array);
        $this->assertArrayHasKey('operator', $array);
        $this->assertArrayHasKey('time', $array);
        $this->assertArrayNotHasKey('otp', $array);
    }

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function testToArrayExcludesOtpEvenWhenSet(): void
    {
        $burnDown = new BurnDown(
            'https://example.com/@bob',
            'operator@example.com',
            new DateTimeImmutable('2024-01-01T00:00:00Z'),
            'test-otp-123'
        );

        $array = $burnDown->toArray();

        $this->assertArrayHasKey('actor', $array);
        $this->assertArrayHasKey('operator', $array);
        $this->assertArrayHasKey('time', $array);
        // otp is a top-level protocol field, not in the message map
        $this->assertArrayNotHasKey('otp', $array);
        // But accessible via getter
        $this->assertSame('test-otp-123', $burnDown->getOtp());
    }

    public function testJsonSerializeNeverIncludesOtp(): void
    {
        $burnDown = new BurnDown(
            'https://example.com/@alice',
            'operator@example.com',
            null,
            'otp-value-456'
        );
        $json = $burnDown->jsonSerialize();
        // otp is a top-level protocol field, never in the message map
        $this->assertArrayNotHasKey('otp', $json);
        $this->assertArrayHasKey('actor', $json);
        $this->assertArrayHasKey('operator', $json);
        $this->assertArrayHasKey('time', $json);
    }

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function testConstructorWithDateTime(): void
    {
        $specificTime = new \DateTime('2024-08-15T10:30:00Z');
        $burnDown = new BurnDown(
            'https://example.com/@alice',
            'operator@example.com',
            $specificTime,
            null
        );

        $array = $burnDown->toArray();

        // Verify the time was converted correctly
        $this->assertSame('2024-08-15T10:30:00+00:00', $array['time']);

        // Verify modifying original DateTime doesn't affect BurnDown (proves immutability)
        $specificTime->modify('+1 day');
        $arrayAfter = $burnDown->toArray();
        $this->assertSame('2024-08-15T10:30:00+00:00', $arrayAfter['time']);
    }
}
