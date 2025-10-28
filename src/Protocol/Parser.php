<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    NotImplementedException,
    ParserException
};
use FediE2EE\PKD\Crypto\Protocol\Actions\{
    Checkpoint,
    RevokeKeyThirdParty
};
use DateTimeImmutable;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\{
    EncryptedAddAuxData,
    EncryptedAddKey,
    EncryptedBurnDown,
    EncryptedFireproof,
    EncryptedMoveIdentity,
    EncryptedRevokeAuxData,
    EncryptedRevokeKey,
    EncryptedUndoFireproof
};
use Exception;
use FediE2EE\PKD\Crypto\{
    PublicKey,
    UtilTrait
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\{
    HPKE,
    HPKEException,
    KEM\DHKEM\DecapsKey
};
use SodiumException;

class Parser
{
    use UtilTrait;

    const UNENCRYPTED_ACTIONS = ['Checkpoint', 'RevokeKeyThirdParty'];

    /**
     * @throws CryptoException
     */
    public function getEncryptedMessage(Bundle $message): EncryptedProtocolMessageInterface
    {
        return match ($message->getAction()) {
            'AddKey' =>
                new EncryptedAddKey($message->getMessage()),
            'AddAuxData' =>
                new EncryptedAddAuxData($message->getMessage()),
            'BurnDown' =>
                new EncryptedBurnDown($message->getMessage()),
            'Fireproof' =>
                new EncryptedFireproof($message->getMessage()),
            'MoveIdentity' =>
                new EncryptedMoveIdentity($message->getMessage()),
            'RevokeAuxData' =>
                new EncryptedRevokeAuxData($message->getMessage()),
            'RevokeKey' =>
                new EncryptedRevokeKey($message->getMessage()),
            'UndoFireproof' =>
                new EncryptedUndoFireproof($message->getMessage()),
            default =>
                throw new CryptoException('Unknown action: ' . $message->getAction()),
        };
    }

    /**
     * @throws CryptoException
     * @throws Exception
     */
    public function getUnencryptedMessage(Bundle $bundle): ProtocolMessageInterface
    {
        $components = $bundle->getMessage();
        if (!array_key_exists('time', $components)) {
            $time = null;
        } elseif (is_null($components['time'])) {
            $time = null;
        } else {
            $time = new DateTimeImmutable($components['time'] );
        }
        return match ($bundle->getAction()) {
            'Checkpoint' =>
                new Checkpoint(
                    $components['from-directory'] ?? '',
                        $components['from-root'] ?? '',
                        PublicKey::fromString($components['from-public-key'] ?? ''),
                        $components['to-directory'] ?? '',
                        $components['to-validated-root'] ?? '',
                    $time
                ),
            'RevokeKeyThirdParty' =>
                new RevokeKeyThirdParty(
                    $components['revocation-token'] ?? ''
                ),
            default =>
                throw new CryptoException('Unknown action: ' . $bundle->getAction()),
        };
    }

    /**
     * @throws BundleException
     */
    public static function fromJson(string $json): Bundle
    {
        return Bundle::fromJson($json);
    }

    /**
     * @api
     *
     * @throws CryptoException
     * @throws HPKEException
     * @throws NotImplementedException
     * @throws ParserException
     * @throws SodiumException
     */
    public function decryptAndParse(
        string $encrypted,
        DecapsKey $decapsKey,
        HPKE $hpke,
        ?PublicKey $publicKey = null,
        string $info = '',
        string $aad = ''
    ): array {
        $decrypted = $hpke->openBase(
            $decapsKey,
            Base64UrlSafe::decodeNoPadding($encrypted),
            aad: $aad,
            info: $info
        );
        return $this->parse($decrypted, $publicKey);
    }

    /**
     * @throws CryptoException
     * @throws ParserException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function parse(
        string $json,
        ?PublicKey $publicKey = null
    ): array {
        $message = static::fromJson($json);
        if (in_array($message->getAction(), self::UNENCRYPTED_ACTIONS, true)) {
            $encrypted = $this->getUnencryptedMessage($message);
        } else {
            // These fields have encryption
            $encrypted = $this->getEncryptedMessage($message);
        }

        if ($publicKey) {
            $signedMessage = new SignedMessage($encrypted, $message->getRecentMerkleRoot());
            if (!$signedMessage->verify($publicKey, $message->getSignature())) {
                throw new ParserException('Signature verification failed');
            }
        }
        $keyMap = $message->getSymmetricKeys();
        return [$encrypted, $keyMap];
    }

    /**
     * @throws BundleException
     * @throws HPKEException
     */
    public function hpkeDecrypt(
        string $encrypted,
        DecapsKey $decapsKey,
        HPKE $hpke,
        string $info = '',
        string $aad = ''
    ): Bundle {
        return static::fromJson(
            $hpke->openBase(
                $decapsKey,
                Base64UrlSafe::decodeNoPadding($encrypted),
                aad: $aad,
                info: $info
            )
        );
    }
}
