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
    ActivityPub\WebFinger,
    Protocol\Actions\BurnDown,
    SecretKey,
    UtilTrait};
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\{
    HPKE,
    HPKEException,
    KEM\DHKEM\EncapsKey
};
use SodiumException;
use function in_array, is_null;

class Handler
{
    use UtilTrait;
    public static ?WebFinger $wf = null;

    public static function getWebFinger(): WebFinger
    {
        if (is_null(self::$wf)) {
            self::$wf = new WebFinger();
        }
        return self::$wf;
    }

    /**
     * Handle a message: Encrypt its attributes with the AttributeKeyMap, then sign it.
     * Returns a Bundle that wraps the signed message.
     *
     * @api
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function handle(
        ProtocolMessageInterface $message,
        SecretKey $secretKey,
        AttributeKeyMap $keyMap,
        string $recentMerkleRoot = ''
    ): Bundle {
        $otp = null;
        if ($message instanceof BurnDown) {
            $otp = $message->getOTP();
        }
        if (!($message instanceof EncryptedProtocolMessageInterface)) {
            if (!in_array($message->getAction(), Parser::PLAINTEXT_ACTIONS, true)) {
                $message = $message->encrypt($keyMap);
            }
        }
        $signedMessage = new SignedMessage($message, $recentMerkleRoot);
        $signature = $signedMessage->sign($secretKey);

        return new Bundle(
            $message->getAction(),
            $message->toArray(),
            $recentMerkleRoot,
            Base64UrlSafe::decodeNoPadding($signature),
            $keyMap,
            otp: $otp,
        );
    }

    /**
     * @api
     * @throws HPKEException
     * @throws JsonException
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
