<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol\Actions;

use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    InputException,
    JsonException,
    NetworkException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\SecretKey;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(AddKey::class)]
class AddKeyTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testConstructorWithDateTimeImmutable(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $specificTime = new DateTimeImmutable('2024-06-15T12:30:45Z');
        $addKey = new AddKey('https://example.com/@alice', $pk, $specificTime);

        $array = $addKey->toArray();

        // Verify the exact time was used
        $this->assertSame('2024-06-15T12:30:45+00:00', $array['time']);
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testConstructorWithDateTime(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        // Create a mutable DateTime (not DateTimeImmutable)
        $specificTime = new DateTime('2024-07-20T15:45:30Z');
        $addKey = new AddKey('https://example.com/@bob', $pk, $specificTime);

        $array = $addKey->toArray();

        // Verify the time was converted correctly via DateTimeImmutable::createFromInterface()
        $this->assertSame('2024-07-20T15:45:30+00:00', $array['time']);

        // Verify that modifying the original DateTime doesn't affect the AddKey
        // (proves we're using immutable internally)
        $specificTime->modify('+1 day');
        $arrayAfter = $addKey->toArray();
        $this->assertSame('2024-07-20T15:45:30+00:00', $arrayAfter['time']);
    }

    /**
     * Test that passing null for time uses current time.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testConstructorWithNullTimeUsesCurrentTime(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $before = new DateTimeImmutable('NOW');
        $addKey = new AddKey('https://example.com/@charlie', $pk, null);
        $after = new DateTimeImmutable('NOW');

        $array = $addKey->toArray();
        $timeStr = $array['time'];
        $time = DateTimeImmutable::createFromFormat(DateTimeInterface::ATOM, $timeStr);

        // Verify time is between before and after
        $this->assertGreaterThanOrEqual($before->getTimestamp(), $time->getTimestamp());
        $this->assertLessThanOrEqual($after->getTimestamp(), $time->getTimestamp());
    }

    /**
     * Test that the else branch (DateTimeInterface conversion) is actually taken.
     * This ensures the mutant that inverts the instanceof check would fail.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testDateTimeInterfaceConversion(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        // Use DateTime explicitly (implements DateTimeInterface but not DateTimeImmutable)
        $mutableTime = new DateTime('2025-01-01T00:00:00Z');
        $addKey = new AddKey('https://example.com/@test', $pk, $mutableTime);

        $array = $addKey->toArray();
        $this->assertArrayHasKey('time', $array);

        // The correct code path is: DateTimeImmutable::createFromInterface($time)
        // If the mutant inverts the check, DateTime would incorrectly be assigned directly
        // (which would fail type check or cause issues)
        $this->assertSame('2025-01-01T00:00:00+00:00', $array['time']);
    }
}
