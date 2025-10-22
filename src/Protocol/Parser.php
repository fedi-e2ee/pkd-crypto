<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\ParserException;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\EncryptedAddKey;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;

class Parser
{
    use UtilTrait;

    public function getEncryptedMessage(Bundle $message): EncryptedProtocolMessageInterface
    {
        switch ($message->getAction()) {
            case 'AddKey':
                return new EncryptedAddKey($message->getMessage());
            default:
                throw new \Exception('Unknown action: ' . $message->getAction());
        }
    }

    public static function fromJson(string $json): Bundle
    {
        return Bundle::fromJson($json);
    }

    public function parse(
        string $json,
        ?PublicKey $publicKey = null
    ): array {
        $message = static::fromJson($json);
        $encrypted = $this->getEncryptedMessage($message);
        if ($publicKey) {
            $signedMessage = new SignedMessage($encrypted, $message->getRecentMerkleRoot());
            if (!$signedMessage->verify($publicKey, $message->getSignature())) {
                throw new ParserException('Signature verification failed');
            }
        }
        $keyMap = $message->getSymmetricKeys();
        return [$encrypted, $keyMap];
    }

    public function hpkeDecrypt(
        string $encrypted,
        DecapsKey $decapsKey,
        HPKE $hpke,
        string $info = '',
        string $aad = ''
    ): Bundle {
        $json = $hpke->openBase($decapsKey, $encrypted, aad: $aad, info: $info);
        return static::fromJson($json);
    }
}
