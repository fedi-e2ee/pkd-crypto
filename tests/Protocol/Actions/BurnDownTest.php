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
    public function testToArrayWithNonNullOtpIncludesOtpKey(): void
    {
        $otpValue = 'test-otp-123';
        $burnDown = new BurnDown(
            'https://example.com/@bob',
            'operator@example.com',
            new DateTimeImmutable('2024-01-01T00:00:00Z'),
            $otpValue
        );

        $array = $burnDown->toArray();

        $this->assertArrayHasKey('actor', $array);
        $this->assertArrayHasKey('operator', $array);
        $this->assertArrayHasKey('time', $array);

        // CRITICAL: otp SHOULD be in the array when it's not null
        $this->assertArrayHasKey('otp', $array);
        $this->assertSame($otpValue, $array['otp']);
    }

    public function testJsonSerializeOtpBehavior(): void
    {
        // With null OTP
        $burnDownNull = new BurnDown(
            'https://example.com/@alice',
            'operator@example.com',
            null,
            null
        );
        $jsonNull = $burnDownNull->jsonSerialize();
        $this->assertArrayNotHasKey('otp', $jsonNull);

        // With non-null OTP
        $burnDownWithOtp = new BurnDown(
            'https://example.com/@alice',
            'operator@example.com',
            null,
            'otp-value-456'
        );
        $jsonWithOtp = $burnDownWithOtp->jsonSerialize();
        $this->assertArrayHasKey('otp', $jsonWithOtp);
        $this->assertSame('otp-value-456', $jsonWithOtp['otp']);
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
