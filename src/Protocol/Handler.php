<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;

class Handler
{
    use UtilTrait;

    public function handle(
        ProtocolMessageInterface $message,
        SecretKey $secretKey,
        AttributeKeyMap $keyMap,
        string $recentMerkleRoot = ''
    ): Bundle {
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

    public function hpkeEncrypt(
        Bundle    $message,
        EncapsKey $encapsKey,
        HPKE      $hpke,
        string    $info = '',
        string    $aad = ''
    ): string {
        return $hpke->sealBase($encapsKey, $message->toJson(), $aad, $info);
    }
}
