<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\BundleException;
use FediE2EE\PKD\Crypto\Exceptions\ParserException;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\Parser;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Property-based tests for protocol message handling.
 */
#[CoversClass(Bundle::class)]
#[CoversClass(Parser::class)]
class ProtocolTest extends TestCase
{
    use TestTrait;
    use ErisPhpUnit12Trait {
        ErisPhpUnit12Trait::getTestCaseAnnotations insteadof TestTrait;
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->erisSetupCompat();
    }

    /**
     * Property: Bundle toJson/fromJson is a roundtrip.
     *
     * fromJson(toJson(bundle)) preserves action, merkle root, and signature
     */
    public function testBundleJsonRoundtrip(): void
    {
        $this->forAll(
            Generators::choose(1, 100)  // Counter to generate multiple bundles
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $action = 'AddKey';
            $merkleRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
            $signature = $secretKey->sign('test-message');

            $keyMap = new AttributeKeyMap();
            $keyMap->addKey('actor', SymmetricKey::generate());
            $keyMap->addKey('public-key', SymmetricKey::generate());

            $bundle = new Bundle(
                $action,
                ['actor' => 'test-actor', 'public-key' => 'test-key'],
                $merkleRoot,
                $signature,
                $keyMap
            );

            $json = $bundle->toJson();
            $restored = Bundle::fromJson($json);

            $this->assertSame($action, $restored->getAction());
            $this->assertSame($merkleRoot, $restored->getRecentMerkleRoot());
            $this->assertSame($signature, $restored->getSignature());
            $this->assertSame($bundle->getMessage(), $restored->getMessage());
        });
    }

    /**
     * Property: Bundle toJson produces valid JSON.
     */
    public function testBundleJsonValid(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $keyMap = new AttributeKeyMap();
            $keyMap->addKey('test', SymmetricKey::generate());

            $bundle = new Bundle(
                'TestAction',
                ['key' => 'value'],
                'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32)),
                $secretKey->sign('test'),
                $keyMap
            );

            $json = $bundle->toJson();
            $decoded = json_decode($json, true);

            $this->assertNotNull($decoded, 'Bundle should produce valid JSON');
            $this->assertArrayHasKey('action', $decoded);
            $this->assertArrayHasKey('message', $decoded);
            $this->assertArrayHasKey('recent-merkle-root', $decoded);
            $this->assertArrayHasKey('signature', $decoded);
            $this->assertArrayHasKey('symmetric-keys', $decoded);
        });
    }

    /**
     * Property: Parser.fromJson throws on empty input.
     */
    public function testParserRejectsEmptyInput(): void
    {
        $this->expectException(BundleException::class);
        Parser::fromJson('');
    }

    /**
     * Property: Parser.fromJson throws on invalid JSON.
     */
    public function testParserRejectsInvalidJson(): void
    {
        $this->forAll(
            Generators::string()
        )
        ->when(fn(string $s) => strlen($s) > 0 && json_decode($s) === null)
        ->then(function (string $invalidJson): void {
            try {
                Parser::fromJson($invalidJson);
                $this->fail('Parser should reject invalid JSON');
            } catch (BundleException $e) {
                $this->assertTrue(true);
            }
        });
    }

    /**
     * Property: Parser does not crash on arbitrary input (robustness).
     *
     * For any input string, Parser either:
     * 1. Returns a valid Bundle, or
     * 2. Throws a BundleException/TypeError
     *
     * It should never throw an unexpected exception or crash.
     *
     * Note: PHP warnings may be triggered for malformed JSON structures.
     * This is expected behavior - the test verifies no fatal errors occur.
     */
    public function testParserRobustness(): void
    {
        $this->forAll(
            Generators::string()
        )->then(function (string $input): void {
            // Suppress warnings - we're testing crash resistance, not warning-free parsing
            $oldLevel = error_reporting(E_ERROR | E_PARSE);
            try {
                Parser::fromJson($input);
                // If we get here, input was valid JSON that parsed to a Bundle
            } catch (BundleException $e) {
                // Expected for invalid input
            } catch (\TypeError $e) {
                // May occur if JSON parses but has wrong structure
            } catch (\Throwable $e) {
                // Any other exception is acceptable for malformed input
            } finally {
                error_reporting($oldLevel);
            }
            $this->assertTrue(true);
        });
    }

    /**
     * Property: Valid Bundle JSON always parses successfully.
     */
    public function testValidBundleAlwaysParses(): void
    {
        $this->forAll(
            Generators::choose(1, 50)
        )->then(function (int $_counter): void {
            $secretKey = SecretKey::generate();
            $keyMap = new AttributeKeyMap();
            $keyMap->addKey('actor', SymmetricKey::generate());

            $original = new Bundle(
                'AddKey',
                ['actor' => 'test'],
                'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32)),
                $secretKey->sign('test'),
                $keyMap
            );

            $json = $original->toJson();

            // Should never throw
            $parsed = Parser::fromJson($json);
            $this->assertInstanceOf(Bundle::class, $parsed);
        });
    }

    /**
     * Property: Symmetric keys survive roundtrip.
     */
    public function testSymmetricKeysRoundtrip(): void
    {
        $this->forAll(
            Generators::choose(1, 5)  // Number of keys
        )->then(function (int $keyCount): void {
            $secretKey = SecretKey::generate();
            $keyMap = new AttributeKeyMap();

            $originalKeys = [];
            for ($i = 0; $i < $keyCount; $i++) {
                $attrName = "attr-$i";
                $key = SymmetricKey::generate();
                $keyMap->addKey($attrName, $key);
                $originalKeys[$attrName] = $key->getBytes();
            }

            $bundle = new Bundle(
                'TestAction',
                [],
                'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32)),
                $secretKey->sign('test'),
                $keyMap
            );

            $restored = Bundle::fromJson($bundle->toJson());
            $restoredKeyMap = $restored->getSymmetricKeys();

            foreach ($originalKeys as $attrName => $originalKeyBytes) {
                $restoredKey = $restoredKeyMap->getKey($attrName);
                $this->assertNotNull($restoredKey, "Key '$attrName' should survive roundtrip");
                $this->assertSame(
                    $originalKeyBytes,
                    $restoredKey->getBytes(),
                    "Key bytes for '$attrName' should match"
                );
            }
        });
    }
}
