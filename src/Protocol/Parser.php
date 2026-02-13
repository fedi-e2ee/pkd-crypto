<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\Exceptions\{BundleException,
    CryptoException,
    InputException,
    JsonException,
    NetworkException,
    NotImplementedException,
    ParserException};
use FediE2EE\PKD\Crypto\Protocol\Actions\{
    BurnDown,
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
use FediE2EE\PKD\Crypto\{
    AttributeEncryption\AttributeKeyMap,
    PublicKey,
    UtilTrait
};
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\HPKE\{
    HPKE,
    HPKEException,
    KEM\DHKEM\DecapsKey,
    KEM\DHKEM\EncapsKey
};
use SodiumException;
use function array_key_exists, in_array, is_null;

class Parser
{
    use UtilTrait;

    /** Actions that are NOT wrapped with HPKE transport encryption. */
    const UNENCRYPTED_ACTIONS = ['BurnDown', 'Checkpoint', 'RevokeKeyThirdParty'];

    /** Actions with no attribute encryption (truly plaintext fields). */
    const PLAINTEXT_ACTIONS = ['Checkpoint', 'RevokeKeyThirdParty'];

    /**
     * Extract a message with encrypted attributes from a Bundle.
     *
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
     * Extract an unencrypted message from the Bundle. If the bundle is encrypted, this automatically
     * decrypts the protocol message's attributes for you.
     *
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function getUnencryptedMessage(Bundle $bundle): ProtocolMessageInterface
    {
        $components = $bundle->getMessage();
        if (!array_key_exists('time', $components)) {
            $time = null;
        } elseif (is_null($components['time'])) {
            $time = null;
        } else {
            $timeStr = (string) $components['time'];
            if (ctype_digit($timeStr)) {
                $time = new DateTimeImmutable('@' . $timeStr);
            } else {
                $time = new DateTimeImmutable($timeStr);
            }
        }
        $action = $bundle->getAction();
        if ($action === 'BurnDown') {
            self::assertAllArrayKeysExist($components, 'actor', 'operator');
        } elseif ($action === 'Checkpoint') {
            self::assertAllArrayKeysExist(
                $components,
                'from-directory',
                'from-root',
                'from-public-key',
                'to-directory',
                'to-validated-root',
            );
        }
        return match ($action) {
            'BurnDown' =>
                new BurnDown(
                    $components['actor'],
                    $components['operator'],
                    $time,
                    $bundle->getOtp(),
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
     * HPKE decrypt a payload and then parse the message.
     *
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
        if (is_null($publicKey)) {
            throw new ParserException('Public key is required for signature verification');
        }
        $decrypted = (new HPKEAdapter($hpke))->open(
            decapsKey: $decapsKey,
            encapsKey: $encapsKey,
            payload: $encrypted,
        );
        return $this->parse($decrypted, $publicKey);
    }

    /**
     * Parse a JSON blob into a ParsedMessage. This verifies the signature on the Protocol Message.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws ParserException
     * @throws SodiumException
     */
    public function parse(
        string $json,
        PublicKey $publicKey
    ): ParsedMessage {
        $message = static::fromJson($json);
        if ($message->getAction() === 'RevokeKeyThirdParty') {
            $rt = $message->getRevocationToken();
            if (is_null($rt)) {
                throw new ParserException('No revocation token');
            }
            return new ParsedMessage(
                new RevokeKeyThirdParty($rt),
                new AttributeKeyMap()
            );
        }
        if (in_array($message->getAction(), self::PLAINTEXT_ACTIONS, true)) {
            $encrypted = $this->getUnencryptedMessage($message);
        } else {
            $encrypted = $this->getEncryptedMessage($message);
        }
        $signedMessage = new SignedMessage(
            $encrypted,
            $message->getRecentMerkleRoot(),
            $message->getSignature()
        );
        if (!$signedMessage->verify($publicKey)) {
            throw new ParserException('Signature verification failed');
        }
        $keyMap = $message->getSymmetricKeys();
        return new ParsedMessage($encrypted, $keyMap);
    }

    /**
     * @api
     * This parses a message without verifying the Protocol Message signature.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function parseUnverified(string $json): ParsedMessage
    {
        $message = static::fromJson($json);
        if ($message->getAction() === 'RevokeKeyThirdParty') {
            $rt = $message->getRevocationToken();
            if (is_null($rt)) {
                throw new ParserException('No revocation token');
            }
            return new ParsedMessage(
                new RevokeKeyThirdParty($rt),
                new AttributeKeyMap()
            );
        }
        if (in_array($message->getAction(), self::PLAINTEXT_ACTIONS, true)) {
            $encrypted = $this->getUnencryptedMessage($message);
        } else {
            $encrypted = $this->getEncryptedMessage($message);
        }
        $keyMap = $message->getSymmetricKeys();
        return new ParsedMessage($encrypted, $keyMap);
    }

    /**
     * @api
     * This parses a message for use in ActivityPub. Rejects BurnDown.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
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
     * Skip signature verification but still reject BurnDown.
     *
     * @throws BundleException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
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
     * Decrypt a Protocol Message using HPKE. The attributes should still be encrypted, but you
     * might have the keys stored in the "symmetric-keys" index.
     *
     * @throws BundleException
     * @throws HPKEException
     * @throws InputException
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
