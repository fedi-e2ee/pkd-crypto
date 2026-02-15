<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    PublicKey,
    SecretKey,
    UtilTrait
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use Override;
use SodiumException;
use function is_null, is_string, json_encode;

//= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#protocol-signatures
//# Every [Protocol Message](#protocol-messages) will contain a digital signature.
final class SignedMessage implements \JsonSerializable
{
    use ToStringTrait;
    use UtilTrait;

    public const PKD_CONTEXT = 'https://github.com/fedi-e2ee/public-key-directory/v1';

    private ProtocolMessageInterface $message;
    private string $recentMerkleRoot;
    private ?string $signature;

    public function __construct(
        ProtocolMessageInterface $message,
        string $recentMerkleRoot,
        ?string $signature = null
    ) {
        $this->message = $message;
        $this->recentMerkleRoot = $recentMerkleRoot;
        $this->signature = $signature;
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public static function init(
        ProtocolMessageInterface $message,
        string $recentMerkleRoot,
        SecretKey $sk
    ): SignedMessage {
        $self = new static($message, $recentMerkleRoot);
        $self->sign($sk);
        return $self;
    }

    /**
     * @throws CryptoException
     */
    public function getDecryptedContents(AttributeKeyMap $keyMap): array
    {
        if ($this->message instanceof EncryptedProtocolMessageInterface) {
            $toArray = $this->decrypt($keyMap)->toArray();
        } else {
            $toArray = $this->message->toArray();
        }
        $data = [
            '!pkd-context' => self::PKD_CONTEXT,
            'action' => $this->message->getAction(),
            'message' => $toArray,
            'recent-merkle-root' => $this->recentMerkleRoot
        ];
        ksort($data);
        return $data;
    }

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#protocol-signatures
    //# Each digital signature will be calculated over the following information
    /**
     * @throws CryptoException
     */
    public function encodeForSigning(): string
    {
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#protocol-signatures
        //# Object keys **MUST** be sorted in ASCII byte order, and there **MUST** be no duplicate keys.
        $encodedMessage = json_encode(
            $this->message,
            JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        if (!is_string($encodedMessage)) {
            throw new CryptoException("Could not encode message for signing");
        }
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#protocol-signatures
        //# To ensure domain separation, we will use Pre-Authentication Encoding
        return $this->preAuthEncode([
            '!pkd-context',
            self::PKD_CONTEXT,
            'action',
            $this->message->getAction(),
            'message',
            $encodedMessage,
            'recent-merkle-root',
            $this->recentMerkleRoot
        ]);
    }

    /**
     * @throws CryptoException
     */
    public function encrypt(AttributeKeyMap $keyMap): ProtocolMessageInterface
    {
        if ($this->message instanceof EncryptedProtocolMessageInterface) {
            throw new CryptoException('message is already encrypted');
        }
        return $this->message->encrypt($keyMap);
    }

    /**
     * @throws CryptoException
     */
    public function decrypt(AttributeKeyMap $keyMap): ProtocolMessageInterface
    {
        if (!($this->message instanceof EncryptedProtocolMessageInterface)) {
            throw new CryptoException('message is not encrypted');
        }
        return $this->message->decrypt($keyMap);
    }

    /**
     * @api
     */
    public function getInnerMessage(): ProtocolMessageInterface
    {
        return $this->message;
    }

    /**
     * @throws NotImplementedException
     * @throws CryptoException
     * @throws SodiumException
     */
    public function sign(SecretKey $key): string
    {
        $this->signature = $key->sign($this->encodeForSigning());
        return $this->getSignature();
    }

    public function getRecentMerkleRoot(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->recentMerkleRoot);
    }

    /**
     * @throws CryptoException
     */
    public function getSignature(): string
    {
        if (is_null($this->signature)) {
            throw new CryptoException('Protocol Message is not signed');
        }
        return Base64UrlSafe::encodeUnpadded($this->signature);
    }

    /**
     * @throws NotImplementedException
     * @throws CryptoException
     * @throws SodiumException
     */
    public function verify(PublicKey $key, ?string $signature = null): bool
    {
        if (is_null($signature)) {
            if (is_null($this->signature)) {
                throw new CryptoException('Protocol Message is not signed');
            }
            $sig = $this->signature;
        } else {
            $sig = Base64UrlSafe::decodeNoPadding($signature);
        }
        $valid = $key->verify($sig, $this->encodeForSigning());
        if ($valid && !is_null($signature)) {
            $this->signature = $sig;
        }
        return $valid;
    }

    /**
     * @throws CryptoException
     */
    public function toArray(): array
    {
        $data = [
            '!pkd-context' => self::PKD_CONTEXT,
            'action' => $this->message->getAction(),
            'message' => $this->message->toArray(),
            'recent-merkle-root' => $this->getRecentMerkleRoot(),
            'signature' => $this->getSignature(),
        ];
        ksort($data);
        return $data;
    }

    /**
     * @throws CryptoException
     */
    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
