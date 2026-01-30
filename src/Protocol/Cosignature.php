<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Merkle\IncrementalTree;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SodiumException;
use function array_key_exists, hash_equals, is_array, is_string, json_decode, json_encode, json_last_error_msg, time;

class Cosignature
{
    use UtilTrait;

    public const CONTEXT = 'fedi-e2ee-v1:cosignature';

    public function __construct(protected IncrementalTree $state)
    {}

    public function append(HistoricalRecord $record, string $expectedMerkleRoot): self
    {
        $clone = clone $this->state;
        $clone->addLeaf($record->serializeForMerkle());
        if (!hash_equals($expectedMerkleRoot, $clone->getEncodedRoot())) {
            throw new CryptoException('Merkle Root mismatch for appended record');
        }
        $this->state = $clone;
        return $this;
    }

    /**
     * @param SecretKey $sk My signing key for this cosignature
     * @param string $hostname HTTP Host of the PKD server to receive the cosignature
     * @return string
     *
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function cosign(SecretKey $sk, string $hostname): string
    {
        $payload = [
            '!pkd-context' => self::CONTEXT,
            'current-time' => (string) (time()),
            'hostname' => $hostname,
            'merkle-root' => $this->state->getEncodedRoot(),
        ];
        $signature = $sk->sign(
            $this->preAuthEncode([
                '!pkd-context', $payload['!pkd-context'],
                'current-time', $payload['current-time'],
                'hostname', $payload['hostname'],
                'merkle-root', $payload['merkle-root'],
            ])
        );
        $payload['signature'] = Base64UrlSafe::encodeUnpadded($signature);
        $encoded = json_encode(
            $payload,
            JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        if (!is_string($encoded)) {
            throw new JsonException('Failed to encode JSON: ' . json_last_error_msg());
        }
        return $encoded;
    }

    /**
     * @param PublicKey $pk
     * @param string $json
     * @return array
     *
     * @throws CryptoException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public static function verifyCosignature(PublicKey $pk, string $json): array
    {
        $payload = json_decode($json, true);
        // Must decode
        if (!is_array($payload)) {
            throw new JsonException('could not decode json: ' . json_last_error_msg());
        }

        // All expected aray keys must exist:
        if (!array_key_exists('!pkd-context', $payload)) {
            throw new CryptoException('No "!pkd-context" found in payload');
        }
        if (!array_key_exists('current-time', $payload)) {
            throw new CryptoException('No timestamp provided in "current-time"');
        }
        if (!array_key_exists('hostname', $payload)) {
            throw new CryptoException('No "hostname" found in payload');
        }
        if (!array_key_exists('merkle-root', $payload)) {
            throw new CryptoException('No "merkle-root" found in payload');
        }
        if (!array_key_exists('signature', $payload)) {
            throw new CryptoException('No "signature" found in payload');
        }

        // Validate inputs:
        if (!hash_equals(self::CONTEXT, $payload['!pkd-context'])) {
            throw new CryptoException('invalid "!pkd-context" value');
        }

        // Check signature
        $verified = $pk->verify(
            Base64UrlSafe::decodeNoPadding($payload['signature']),
            self::preAuthEncode([
                '!pkd-context', $payload['!pkd-context'],
                'current-time', $payload['current-time'],
                'hostname', $payload['hostname'],
                'merkle-root', $payload['merkle-root'],
            ])
        );
        if (!$verified) {
            throw new CryptoException('invalid signature');
        }
        return $payload;
    }

    public function getTree(): IncrementalTree
    {
        return $this->state;
    }
}
