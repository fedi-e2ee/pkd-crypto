<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\Cosignature;
use FediE2EE\PKD\Crypto\Protocol\HistoricalRecord;
use FediE2EE\PKD\Crypto\Protocol\Parser;
use FediE2EE\PKD\Crypto\Protocol\SignedMessage;
use FediE2EE\PKD\Crypto\SecretKey;
use PHPUnit\Framework\TestCase;
use SodiumException;

class CosignatureTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws JsonException
     * @throws SodiumException
     */
    public function testCosign(): void
    {
        $sk = SecretKey::generate();
        $tree = new IncrementalTree();
        $cosignature = new Cosignature($tree);

        $expected = "pkd-mr-v1:OonfFFdPSEr0q5ELC_fjzdxRSiPyblb1SXBK2GFzLBw";
        $record = HistoricalRecord::fromArray([
            'encrypted-message' =>
                '{"!pkd-context":"https://github.com/fedi-e2ee/public-key-directory/v1","action":"AddKey","message":{"actor":"0ZQvDXvULF_S-2rDeHTXUV77R9cCBTS6dRoeYt0v-Mq3zAlrzn1kcynY6ZWT_tVYRoO-zv2vgsVFB7rnFwGm25baXAxMvph7nK8F0Zr1QQQ-WLdE7ys_QBcywAFUyw","public-key":"-V_2U-9A5sjpk2eBTtZH8JCCBq2bQsU_iV4yQRwqrlEoYV9ArlHuRpBmx8SrXYzVTOQjTvNaizcwEn_v9p8kutHRhruzpSzUIrBYCKiWl4zc-fLKO4gasD-W4w","time":"2025-12-13T19:06:44+00:00"},"recent-merkle-root":"cGtkLW1yLXYxOkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE","signature":"S3lPUDQ3Zy1adFA1WmhoUHg3N2JEd3RRRTl3NzBwMzI5LU5WRS1EMEVWZGQ3SE5vNTYxZXVaWDBYRkd5RmZaV2NlcmRGOWFaLUZrVmhhWVVMbzliQ3c"}',
            'publickeyhash' =>
                '5c52f4d19c120ca2f088a2c640c90605fe8ee363488cd999fa3b57fb9e5121f0',
            'signature' =>
                'Ex9HPWvWP2BO8_7S1qyC0qDPsJQgJe1pkqURYdiTIMBjH3ew5kYayauk9pXoSdiHKe1aQklI3ruamHSd1EPsAg',
        ]);
        $beforeAppend = $cosignature->getTree()->toJson();
        $cosignature->append($record, $expected);
        $afterAppend = $cosignature->getTree()->toJson();
        $this->assertSame($expected, $cosignature->getTree()->getEncodedRoot());
        $this->assertNotSame($beforeAppend, $afterAppend);

        $cosigned = $cosignature->cosign($sk, 'http://localhost');
        $this->assertIsString($cosigned);
        $results = Cosignature::verifyCosignature($sk->getPublicKey(), $cosigned);
        $this->assertIsArray($results);
        $this->assertArrayHasKey('!pkd-context', $results);
        $this->assertArrayHasKey('current-time', $results);
        $this->assertArrayHasKey('hostname', $results);
        $this->assertArrayHasKey('merkle-root', $results);
        $this->assertArrayHasKey('signature', $results);
    }
}
