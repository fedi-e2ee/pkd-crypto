<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    InputException,
    JsonException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\Protocol\{
    Actions\AddKey,
    Bundle,
    Handler,
    SignedMessage
};
use FediE2EE\PKD\Crypto\SecretKey;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(Bundle::class)]
class BundleTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testToSignedMessage(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $this->assertIsString($addKey->toString());
        $signed = new SignedMessage($addKey, $recent);
        $signature = $signed->sign($sk);

        $bundle = new Bundle(
            $addKey->getAction(),
            $addKey->jsonSerialize(),
            $recent,
            Base64UrlSafe::decodeNoPadding($signature),
            new AttributeKeyMap()
        );

        $signedFromBundle = $bundle->toSignedMessage();
        $this->assertTrue($signedFromBundle->verify($pk));
    }

    /**
     * @throws SodiumException
     */
    public static function invalidFromFuzzer(): array
    {
        return [
            [sodium_hex2bin('18181818182d2d302d2d2d2d2d2d7e50f3')],
            [sodium_hex2bin('402f2f2f2f2f2f2f2f2f2f2f2f2f30')],
        ];
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    #[DataProvider("invalidFromFuzzer")]
    public function testInvalidInput(string $input): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson($input);
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testToJsonContainsPkdContext(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $signed = new SignedMessage($addKey, $recent);
        $signature = $signed->sign($sk);

        $bundle = new Bundle(
            $addKey->getAction(),
            $addKey->jsonSerialize(),
            $recent,
            Base64UrlSafe::decodeNoPadding($signature),
            new AttributeKeyMap()
        );

        $json = $bundle->toJson();
        $this->assertIsString($json);

        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);

        // Verify !pkd-context is present and has correct value
        $this->assertArrayHasKey('!pkd-context', $decoded);
        $this->assertSame(SignedMessage::PKD_CONTEXT, $decoded['!pkd-context']);

        // Verify all required keys exist with correct association
        $this->assertArrayHasKey('action', $decoded);
        $this->assertSame('AddKey', $decoded['action']);

        $this->assertArrayHasKey('message', $decoded);
        $this->assertIsArray($decoded['message']);

        $this->assertArrayHasKey('recent-merkle-root', $decoded);
        $this->assertIsString($decoded['recent-merkle-root']);

        $this->assertArrayHasKey('signature', $decoded);
        $this->assertIsString($decoded['signature']);

        $this->assertArrayHasKey('symmetric-keys', $decoded);
        $this->assertIsArray($decoded['symmetric-keys']);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testJsonRoundTrip(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $signed = new SignedMessage($addKey, $recent);
        $signature = $signed->sign($sk);

        $bundle = new Bundle(
            $addKey->getAction(),
            $addKey->jsonSerialize(),
            $recent,
            Base64UrlSafe::decodeNoPadding($signature),
            new AttributeKeyMap()
        );

        // Round-trip through JSON
        $json = $bundle->toJson();
        $restored = Bundle::fromJson($json);

        $this->assertSame($bundle->getAction(), $restored->getAction());
        $this->assertSame($bundle->getSignature(), $restored->getSignature());
        $this->assertSame($bundle->getRecentMerkleRoot(), $restored->getRecentMerkleRoot());
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonMissingSymmetricKeys(): void
    {
        $json = json_encode([
            'action' => 'AddKey',
            'message' => ['actor' => 'test', 'public-key' => 'test'],
            'recent-merkle-root' => 'pkd-mr-v1:test',
            'signature' => 'test',
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonMissingAction(): void
    {
        $json = json_encode([
            'symmetric-keys' => [],
            'message' => ['actor' => 'test', 'public-key' => 'test'],
            'recent-merkle-root' => 'pkd-mr-v1:test',
            'signature' => 'test',
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonMissingMessage(): void
    {
        $json = json_encode([
            'symmetric-keys' => [],
            'action' => 'AddKey',
            'recent-merkle-root' => 'pkd-mr-v1:test',
            'signature' => 'test',
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonMissingMerkleRoot(): void
    {
        $json = json_encode([
            'symmetric-keys' => [],
            'action' => 'AddKey',
            'message' => ['actor' => 'test', 'public-key' => 'test'],
            'signature' => 'test',
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonInvalidJson(): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson('not valid json');
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonEmptyString(): void
    {
        $this->expectException(BundleException::class);
        $this->expectExceptionMessage('Empty JSON string');
        Bundle::fromJson('');
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonInvalidJsonContainsErrorMessage(): void
    {
        try {
            Bundle::fromJson('{invalid json}');
            $this->fail('Expected BundleException was not thrown');
        } catch (BundleException $e) {
            // Verify the message contains both the prefix and the JSON error
            $this->assertStringContainsString('Invalid JSON string:', $e->getMessage());
            // The json_last_error_msg() should also be included
            $this->assertMatchesRegularExpression('/Invalid JSON string:.*/', $e->getMessage());
        }
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonNotObject(): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson('"just a string"');
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testToString(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $addKey = new AddKey('https://example.com/@alice', $pk);
        $signed = new SignedMessage($addKey, $recent);
        $signature = $signed->sign($sk);

        $bundle = new Bundle(
            $addKey->getAction(),
            $addKey->jsonSerialize(),
            $recent,
            Base64UrlSafe::decodeNoPadding($signature),
            new AttributeKeyMap()
        );

        // toString and __toString should return the same as toJson
        $this->assertSame($bundle->toJson(), $bundle->toString());
        $this->assertSame($bundle->toJson(), (string) $bundle);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testWithKeyMap(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $keyMap = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');
        $recent = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        $addKey = new AddKey('https://example.com/@alice', $pk);
        $handler = new Handler();
        $bundle = $handler->handle($addKey, $sk, $keyMap, $recent);
        $toJson = $bundle->toJson();

        $decoded = json_decode($toJson, true);
        $this->assertArrayHasKey('symmetric-keys', $decoded);
        unset($decoded['symmetric-keys']);

        $pass1 = Bundle::fromJson($toJson)->toJson();
        $pass2 = Bundle::fromJson(json_encode($decoded), $keyMap)->toJson();
        $this->assertSame($pass1, $pass2);

        $this->expectException(InputException::class);
        Bundle::fromJson(json_encode($decoded));
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws InputException
     * @throws JsonException
     * @throws RandomException
     */
    public function testBurnDownOtpRoundTrip(): void
    {
        $otp = Base64UrlSafe::encodeUnpadded(random_bytes(16));
        $json = json_encode([
            '!pkd-context' => 'https://github.com/fedi-e2ee/public-key-directory/v1',
            'action' => 'BurnDown',
            'message' => [
                'actor' => 'test-actor',
                'operator' => 'test-operator',
                'time' => '2025-01-01T00:00:00+00:00',
            ],
            'otp' => $otp,
            'recent-merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32)),
            'signature' => Base64UrlSafe::encodeUnpadded(random_bytes(64)),
            'symmetric-keys' => [],
        ]);

        $bundle = Bundle::fromJson($json);
        $this->assertSame('BurnDown', $bundle->getAction());
        $this->assertSame($otp, $bundle->getOtp());

        // Round-trip: toJson must include 'otp' key
        $output = json_decode($bundle->toJson(), true);
        $this->assertArrayHasKey('otp', $output);
        $this->assertSame($otp, $output['otp']);

        // Keys must be sorted (otp before recent-merkle-root)
        $keys = array_keys($output);
        $sortedKeys = $keys;
        sort($sortedKeys);
        $this->assertSame($sortedKeys, $keys, 'JSON keys must be sorted');
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws InputException
     * @throws RandomException
     */
    public function testNonBurnDownIgnoresOtp(): void
    {
        $json = json_encode([
            'action' => 'AddKey',
            'message' => ['actor' => 'test', 'public-key' => 'test', 'time' => '2025-01-01T00:00:00+00:00'],
            'otp' => 'should-be-ignored',
            'recent-merkle-root' => 'pkd-mr-v1:test',
            'signature' => Base64UrlSafe::encodeUnpadded(random_bytes(64)),
            'symmetric-keys' => [],
        ]);

        $bundle = Bundle::fromJson($json);
        $this->assertSame('AddKey', $bundle->getAction());
        $this->assertNull($bundle->getOtp());
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonWithKeyMapMissingAction(): void
    {
        $keyMap = new AttributeKeyMap();
        $json = json_encode([
            // Missing 'action' key
            'message' => ['actor' => 'test', 'public-key' => 'test'],
            'recent-merkle-root' => 'pkd-mr-v1:test',
            'signature' => Base64UrlSafe::encodeUnpadded('test'),
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json, $keyMap);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonWithKeyMapMissingMessage(): void
    {
        $keyMap = new AttributeKeyMap();
        $json = json_encode([
            'action' => 'AddKey',
            // Missing 'message' key
            'recent-merkle-root' => 'pkd-mr-v1:test',
            'signature' => Base64UrlSafe::encodeUnpadded('test'),
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json, $keyMap);
    }

    /**
     * @throws BundleException
     * @throws CryptoException
     */
    public function testFromJsonWithKeyMapMissingMerkleRoot(): void
    {
        $keyMap = new AttributeKeyMap();
        $json = json_encode([
            'action' => 'AddKey',
            'message' => ['actor' => 'test', 'public-key' => 'test'],
            'signature' => Base64UrlSafe::encodeUnpadded('test'),
            // Missing 'recent-merkle-root' key
        ]);

        $this->expectException(InputException::class);
        Bundle::fromJson($json, $keyMap);
    }
}
