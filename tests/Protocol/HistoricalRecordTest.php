<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Protocol\HistoricalRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HistoricalRecord::class)]
class HistoricalRecordTest extends TestCase
{
    public function testHappyPath(): void
    {
        $hr = HistoricalRecord::fromArray([
            'encrypted-message' => 'dholes are majestic',
            'publickeyhash' => hash('sha256', 'uwu'),
            'signature' => hash('sha512', 'OwO'),
        ]);
        $this->assertInstanceOf(HistoricalRecord::class, $hr);

        $this->assertSame(
            '30e8a27cf6bfa14c7c83bed629646882822655e1aadfb2edb251eaaf9c9d1754',
            hash('sha256', $hr->serializeForMerkle())
        );
    }

    public function testMissingMessage(): void
    {
        $this->expectExceptionMessage('Missing "encrypted-message" key');
        $this->expectException(JsonException::class);
        HistoricalRecord::fromArray([
            'publickeyhash' => hash('sha256', 'uwu'),
            'signature' => hash('sha512', 'OwO'),
        ]);
    }

    public function testMissingPKHash(): void
    {
        $this->expectExceptionMessage('Missing "publickeyhash" key');
        $this->expectException(JsonException::class);
        HistoricalRecord::fromArray([
            'encrypted-message' => 'dholes are majestic',
            'signature' => hash('sha512', 'OwO'),
        ]);
    }

    public function testMissingSignature(): void
    {
        $this->expectExceptionMessage('Missing "signature" key');
        $this->expectException(JsonException::class);
        HistoricalRecord::fromArray([
            'encrypted-message' => 'dholes are majestic',
            'publickeyhash' => hash('sha256', 'uwu'),
        ]);
    }
}
