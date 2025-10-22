<?php
declare(strict_types=1);

namespace FediE2EE\PKDServer\Tests\Crypto\Compliance;

use Exception;
use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Class CryptoShredTest
 * @package FediE2EE\PKDServer\Tests\Crypto\Compliance
 */
#[CoversClass(Version1::class)]
class Version1Test extends TestCase
{
    protected function getBasicData(): array
    {
        $v1 = new Version1();
        try {
            $ikm = SymmetricKey::generate();
            $merkle = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));
        } catch (Exception $ex) {
            $this->markTestIncomplete('PHP RNG failed');
        }
        return [$v1, $ikm, $merkle];
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testCryptoShred(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);
        $decrypted = $v1->decryptAttribute($attribute, $encrypted, $ikm, $merkle);
        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testInvalidHMAC(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid authentication tag');
        $v1->decryptAttribute($attribute, $encrypted, new SymmetricKey(str_repeat("\xff", 32)), $merkle);
    }

    /**
     * @throws CryptoException
     * @throws Exception
     */
    public function testInvalidPlaintextCommitment(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid plaintext commitment');
        $v1->decryptAttribute($attribute, $encrypted, $ikm, random_bytes(32));
    }

    /**
     * @throws CryptoException
     */
    public function testInvalidVersion(): void
    {
        [$v1, $ikm, $merkle] = $this->getBasicData();
        $attribute = 'actor-id';
        $plaintext = 'https://fluffy.example/users/soatok';

        $encrypted = $v1->encryptAttribute($attribute, $plaintext, $ikm, $merkle);
        $encrypted[0] = "\x00";

        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid version');
        $v1->decryptAttribute($attribute, $encrypted, $ikm, $merkle);
    }
}
