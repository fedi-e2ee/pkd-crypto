<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\BundleException;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(Bundle::class)]
class BundleTest extends TestCase
{
    /**
     * @throws CryptoException
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
            $signature,
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
     * @throws InputException
     */
    #[DataProvider("invalidFromFuzzer")]
    public function testInvalidInput(string $input): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson($input);
    }

    /**
     * @throws CryptoException
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
            $signature,
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
            $signature,
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
     * @throws InputException
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
     * @throws InputException
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
     * @throws InputException
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
     * @throws InputException
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
     * @throws InputException
     */
    public function testFromJsonInvalidJson(): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson('not valid json');
    }

    /**
     * @throws BundleException
     * @throws InputException
     */
    public function testFromJsonNotObject(): void
    {
        $this->expectException(BundleException::class);
        Bundle::fromJson('"just a string"');
    }

    /**
     * @throws CryptoException
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
            $signature,
            new AttributeKeyMap()
        );

        // toString and __toString should return the same as toJson
        $this->assertSame($bundle->toJson(), $bundle->toString());
        $this->assertSame($bundle->toJson(), (string) $bundle);
    }
}
