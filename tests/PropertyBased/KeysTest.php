<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use FediE2EE\PKD\Crypto\SymmetricKey;
use PHPUnit\Framework\TestCase;
use SodiumException;

class KeysTest extends TestCase
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

    public function testSymmetricKeyRoundTrip(): void
    {
        $key = SymmetricKey::generate();
        $wrongKey = SymmetricKey::generate();

        $this->forAll(
            Generators::choose(1, 1000)
        )->then(function (int $length) use ($key, $wrongKey): void {
            $plaintext = random_bytes($length);
            $this->assertSame($plaintext, $key->decrypt($key->encrypt($plaintext)));
            $this->assertSame($plaintext, $key->decrypt($key->encrypt($plaintext, 'foo'), 'foo'));

            $ct = $key->encrypt($plaintext, 'foobar');
            try {
                $key->decrypt($ct);
                $this->fail('decryption should have failed: wrong AAD');
            } catch (SodiumException) {
                $this->assertNotSame($ct, $plaintext);
            }

            try {
                $wrongKey->decrypt($ct);
                $this->fail('decryption should have failed: wrong key');
            } catch (SodiumException) {
                $this->assertNotSame($ct, $plaintext);
            }

            $ct2 = $key->encrypt($plaintext, 'foobar');
            $this->assertNotSame($ct2, $ct);
        });
    }
}
