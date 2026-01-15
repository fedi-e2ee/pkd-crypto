<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\ActivityPub;

use FediE2EE\PKD\Crypto\ActivityPub\WebFinger;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NetworkException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use ParagonIE\Certainty\Exception\CertaintyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use SodiumException;

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

    #[Group('network')]
    #[DataProvider("knownAnswers")]
    public function testKnownAnswers(string $input, string $expected): void
    {
        $actual = (new WebFinger())->canonicalize($input);
        $this->assertSame($expected, $actual, $input);
    }

    #[Group('network')]
    public function testRemoteFetchLocation(): void
    {
        $fetcher = (new WebFinger())->getCaCertFetcher();
        $filePath = $fetcher->getLatestBundle()->getFilePath();
        $expected = dirname(__DIR__, 2) . '/cache';
        $this->assertStringStartsWith($expected, $filePath);
    }

    /**
     * @throws CertaintyException
     * @throws SodiumException
     */
    private function createWebFingerWithMock(MockHandler $mock): WebFinger
    {
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);
        return new WebFinger($client);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testCanonicalizeHttpsUrl(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        $url = 'https://example.com/users/test';
        $this->assertSame($url, $webFinger->canonicalize($url));
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testCanonicalizeHttpToHttps(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        // lowercase http:// should become https://
        $result = $webFinger->canonicalize('http://example.com/users/test');
        $this->assertSame('https://example.com/users/test', $result);
    }

    public static function weirdInputs(): array
    {
        return [
            ['https://user@exmaple.com'],
            ['https://example.com/users/http://example.net/users/alice'],
            ['userhttps://foo.com@example.com@example.net']
        ];
    }

    /**
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    #[DataProvider("weirdInputs")]
    public function testCanonicalEdgeCases(string $weird): void
    {
        $webFinger = new WebFinger();
        $this->expectException(InputException::class);
        $webFinger->canonicalize($weird);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testUrlCacheBehavior(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        $result1 = $webFinger->canonicalize('https://example.com/users/testuser');
        $result2 = $webFinger->canonicalize('https://example.com/users/testuser');

        $this->assertSame($result1, $result2);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testWebFingerCacheBehavior(): void
    {
        $webFingerResponse = json_encode([
            'links' => [
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/testuser'
                ]
            ]
        ]);

        // Mock should only be called once due to caching
        $mock = new MockHandler([
            new Response(200, [], $webFingerResponse),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        // Use the exact same string for both calls (cache key is the original input)
        $input = 'testuser@example.com';
        $result1 = $webFinger->canonicalize($input);
        $result2 = $webFinger->canonicalize($input);

        $this->assertSame($result1, $result2);
        $this->assertSame('https://example.com/users/testuser', $result1);
        $this->assertSame(0, $mock->count());
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testClearCache(): void
    {
        $webFingerResponse = json_encode([
            'links' => [
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/testuser'
                ]
            ]
        ]);

        // Two responses for two HTTP calls
        $mock = new MockHandler([
            new Response(200, [], $webFingerResponse),
            new Response(200, [], $webFingerResponse),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $webFinger->canonicalize('@testuser@example.com');
        $webFinger->clearWebFingerCache();
        $webFinger->canonicalize('@testuser@example.com');

        // Both responses should have been used
        $this->assertSame(0, $mock->count());
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testHandleWithoutAtThrows(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Actor handle must contain exactly one @');
        $webFinger->canonicalize('nodomainsymbol');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testMultipleLeadingAtThrows(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Actor handle must contain exactly one @');
        $webFinger->canonicalize('@@example.com'); // After ltrim becomes 'example.com' with no @
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testEmptyDomainThrows(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Invalid actor handle format');
        $webFinger->canonicalize('@username@'); // Empty domain
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testInvalidJsonThrows(): void
    {
        $mock = new MockHandler([
            new Response(200, [], 'not valid json'),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $this->expectException(JsonException::class);
        $this->expectExceptionMessage('Invalid JSON');
        $webFinger->canonicalize('@user@example.com');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testMissingLinksThrows(): void
    {
        $mock = new MockHandler([
            new Response(200, [], '{"subject": "acct:user@example.com"}'),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('missing "links" array');
        $webFinger->canonicalize('@user@example.com');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testLinksNotArrayThrows(): void
    {
        $mock = new MockHandler([
            new Response(200, [], '{"links": "not an array"}'),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('missing "links" array');
        $webFinger->canonicalize('@user@example.com');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testSkipsIncompleteLinkObjects(): void
    {
        $response = json_encode([
            'links' => [
                ['rel' => 'self'], // Missing type and href
                ['type' => 'application/activity+json'], // Missing rel and href
                ['href' => 'https://example.com'], // Missing rel and type
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/test'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        // Should skip incomplete links and find the complete one
        $result = $webFinger->canonicalize('@user@example.com');
        $this->assertSame('https://example.com/users/test', $result);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testSkipsNonSelfRel(): void
    {
        $response = json_encode([
            'links' => [
                [
                    'rel' => 'http://webfinger.net/rel/profile-page',
                    'type' => 'text/html',
                    'href' => 'https://example.com/@user'
                ],
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/user'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $result = $webFinger->canonicalize('@user@example.com');
        $this->assertSame('https://example.com/users/user', $result);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testSkipsNonActivityPubType(): void
    {
        $response = json_encode([
            'links' => [
                [
                    'rel' => 'self',
                    'type' => 'text/html',
                    'href' => 'https://example.com/@user'
                ],
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/user'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $result = $webFinger->canonicalize('@user@example.com');
        $this->assertSame('https://example.com/users/user', $result);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testSkipsInvalidHrefUrl(): void
    {
        $response = json_encode([
            'links' => [
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'not-a-valid-url'
                ],
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/user'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $result = $webFinger->canonicalize('@user@example.com');
        $this->assertSame('https://example.com/users/user', $result);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testThrowsWhenNoMatchingLink(): void
    {
        $response = json_encode([
            'links' => [
                [
                    'rel' => 'http://webfinger.net/rel/profile-page',
                    'type' => 'text/html',
                    'href' => 'https://example.com/@user'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('No canonical URL found');
        $webFinger->canonicalize('@user@example.com');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testStripsLeadingAt(): void
    {
        $response = json_encode([
            'links' => [
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/user'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        // With leading @
        $result = $webFinger->canonicalize('@user@example.com');
        $this->assertSame('https://example.com/users/user', $result);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testHandleWithoutLeadingAt(): void
    {
        $response = json_encode([
            'links' => [
                [
                    'rel' => 'self',
                    'type' => 'application/activity+json',
                    'href' => 'https://example.com/users/user'
                ]
            ]
        ]);

        $mock = new MockHandler([
            new Response(200, [], $response),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        // Without leading @
        $result = $webFinger->canonicalize('user@example.com');
        $this->assertSame('https://example.com/users/user', $result);
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testJsonNotObjectThrows(): void
    {
        $mock = new MockHandler([
            new Response(200, [], '["array", "instead", "of", "object"]'),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $this->expectException(JsonException::class);
        $webFinger->canonicalize('@user@example.com');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testJsonNullThrows(): void
    {
        $mock = new MockHandler([
            new Response(200, [], 'null'),
        ]);

        $webFinger = $this->createWebFingerWithMock($mock);

        $this->expectException(JsonException::class);
        $webFinger->canonicalize('@user@example.com');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testUppercaseProtocolInUrl(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());
        $this->expectException(NetworkException::class);
        $this->expectExceptionMessage('Invalid URL provided');
        $webFinger->canonicalize('HTTP://example.com/users/test');
    }

    /**
     * @throws CertaintyException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function testHandleWithMultipleAtSymbols(): void
    {
        $webFinger = $this->createWebFingerWithMock(new MockHandler());

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Parse error: domain contains @');
        $webFinger->canonicalize('user@host@extra.com');
    }
}
