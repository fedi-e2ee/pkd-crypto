<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    JsonException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    SecretKey,
    UtilTrait
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\{
    HPKE,
    HPKEException,
    KEM\DHKEM\EncapsKey
};
use SodiumException;

class Handler
{
    use UtilTrait;

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     * @api
     */
    public function handle(
        ProtocolMessageInterface $message,
        SecretKey $secretKey,
        AttributeKeyMap $keyMap,
        string $recentMerkleRoot = ''
    ): Bundle {
        if (!($message instanceof EncryptedProtocolMessageInterface)) {
            if (!$keyMap->isEmpty()) {
                // We assume the intention was to be encrypted, so we encrypt it.
                $message = $message->encrypt($keyMap);
            }
        }
        $signedMessage = new SignedMessage($message, $recentMerkleRoot);
        $signature = $signedMessage->sign($secretKey);

        return new Bundle(
            $message->getAction(),
            $message->toArray(),
            $recentMerkleRoot,
            $signature,
            $keyMap
        );
    }

    /**
     * @throws JsonException
     * @api
     */
    public function hpkeEncrypt(
        Bundle    $bundle,
        EncapsKey $encapsKey,
        HPKE      $hpke,
    ): string {
        return (new HPKEAdapter($hpke))->seal(
            encapsKey: $encapsKey,
            plaintext: $bundle->toJson(),
        );
    }
}
