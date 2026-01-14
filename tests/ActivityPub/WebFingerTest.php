<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\ActivityPub;

use FediE2EE\PKD\Crypto\ActivityPub\WebFinger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(WebFinger::class)]
class WebFingerTest extends TestCase
{
    public static function knownAnswers(): array
    {
        return [
            ['@fedie2ee@mastodon.social', 'https://mastodon.social/ap/users/115428847654719749'],
            ['@soatok@furry.engineer', 'https://furry.engineer/users/soatok'],
            ['@evan@cosocial.ca', 'https://cosocial.ca/users/evan'],
        ];
    }

    #[DataProvider("knownAnswers")]
    public function testKnownAnswers(string $input, string $expected): void
    {
        $actual = (new WebFinger())->canonicalize($input);
        $this->assertSame($expected, $actual, $input);
    }

    public function testRemoteFetchLocation(): void
    {
        $fetcher = (new WebFinger())->getCaCertFetcher();
        $filePath = $fetcher->getLatestBundle()->getFilePath();
        $expected = dirname(__DIR__, 2) . '/cache';
        $this->assertStringStartsWith($expected, $filePath);
    }
}
