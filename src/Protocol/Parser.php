<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    InputException,
    NotImplementedException,
    ParserException
};
use FediE2EE\PKD\Crypto\Protocol\Actions\{
    BurnDown,
    Checkpoint,
    RevokeKeyThirdParty
};
use DateTimeImmutable;
use FediE2EE\PKD\Crypto\Protocol\EncryptedActions\{
    EncryptedAddAuxData,
    EncryptedAddKey,
    EncryptedFireproof,
    EncryptedMoveIdentity,
    EncryptedRevokeAuxData,
    EncryptedRevokeKey,
    EncryptedUndoFireproof
};
use Exception;
use FediE2EE\PKD\Crypto\{
    AttributeEncryption\AttributeKeyMap,
    PublicKey,
    UtilTrait
};
use ParagonIE\HPKE\{
    HPKE,
    HPKEException,
    KEM\DHKEM\DecapsKey,
    KEM\DHKEM\EncapsKey
};
use SodiumException;

class Parser
{
    use UtilTrait;

    const UNENCRYPTED_ACTIONS = ['BurnDown', 'Checkpoint', 'RevokeKeyThirdParty'];

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
        $action = $bundle->getAction();
        if ($action === 'BurnDown') {
            self::assertAllArrayKeysExist($components, 'actor', 'operator', 'otp');
        } elseif ($action === 'Checkpoint') {
            self::assertAllArrayKeysExist(
                $components,
                'from-directory',
                'from-root',
                'from-public-key',
                'to-directory',
                'to-validated-root',
            );
        } elseif ($action === 'RevokeKeyThirdParty') {
            self::assertAllArrayKeysExist($components, 'revocation-token');
        }
        return match ($action) {
            'BurnDown' =>
                new BurnDown(
                    $components['actor'],
                    $components['operator'],
                    $time,
                    $components['otp'],
                ),
            'Checkpoint' =>
                new Checkpoint(
                    $components['from-directory'],
                        $components['from-root'],
                        PublicKey::fromString($components['from-public-key']),
                        $components['to-directory'],
                        $components['to-validated-root'],
                    $time
                ),
            'RevokeKeyThirdParty' =>
                new RevokeKeyThirdParty(
                    $components['revocation-token']
                ),
            default =>
                throw new CryptoException('Unknown action: ' . $bundle->getAction()),
        };
    }

    /**
     * @throws BundleException
     * @throws InputException
     */
    public static function fromJson(string $json, ?AttributeKeyMap $symmetricKeys = null): Bundle
    {
        return Bundle::fromJson($json, $symmetricKeys);
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
        EncapsKey $encapsKey,
        HPKE $hpke,
        ?PublicKey $publicKey = null
    ): ParsedMessage {
        $decrypted = (new HPKEAdapter($hpke))->open(
            decapsKey: $decapsKey,
            encapsKey: $encapsKey,
            payload: $encrypted,
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
        PublicKey $publicKey
    ): ParsedMessage {
        $message = static::fromJson($json);
        if (in_array($message->getAction(), self::UNENCRYPTED_ACTIONS, true)) {
            $encrypted = $this->getUnencryptedMessage($message);
        } else {
            // These fields have encryption
            $encrypted = $this->getEncryptedMessage($message);
        }
        $signedMessage = new SignedMessage($encrypted, $message->getRecentMerkleRoot());
        if (!$signedMessage->verify($publicKey, $message->getSignature())) {
            throw new ParserException('Signature verification failed');
        }
        $keyMap = $message->getSymmetricKeys();
        return new ParsedMessage($encrypted, $keyMap);
    }

    /**
     * @api
     *
     * @throws BundleException
     * @throws CryptoException
     */
    public function parseUnverified(string $json): ParsedMessage
    {
        $message = static::fromJson($json);
        if (in_array($message->getAction(), self::UNENCRYPTED_ACTIONS, true)) {
            $encrypted = $this->getUnencryptedMessage($message);
        } else {
            // These fields have encryption
            $encrypted = $this->getEncryptedMessage($message);
        }
        $keyMap = $message->getSymmetricKeys();
        return new ParsedMessage($encrypted, $keyMap);
    }

    /**
     * @api
     *
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws ParserException
     * @throws SodiumException
     */
    public function parseForActivityPub(
        string $json,
        PublicKey $publicKey
    ): ParsedMessage {
        $parsed = $this->parse($json, $publicKey);
        if ($parsed->getMessage()->getAction() === 'BurnDown') {
            throw new ParserException('BurnDown must not be sent over ActivityPub');
        }
        return $parsed;
    }

    /**
     * @api
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws ParserException
     */
    public function parseUnverifiedForActivityPub(string $json): ParsedMessage
    {
        $parsed = $this->parseUnverified($json);
        if ($parsed->getMessage()->getAction() === 'BurnDown') {
            throw new ParserException('BurnDown must not be sent over ActivityPub');
        }
        return $parsed;
    }

    /**
     * @throws BundleException
     * @throws HPKEException
     */
    public function hpkeDecrypt(
        string $encrypted,
        DecapsKey $decapsKey,
        EncapsKey $encapsKey,
        HPKE $hpke
    ): Bundle {
        return static::fromJson(
            (new HPKEAdapter($hpke))->open(
                decapsKey: $decapsKey,
                encapsKey: $encapsKey,
                payload: $encrypted,
            )
        );
    }
}
