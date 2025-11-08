<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\AttributeEncryption\Version1;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\UtilTrait;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Override;
use SodiumException;

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

    public static function init(
        ProtocolMessageInterface $message,
        string $recentMerkleRoot,
        SecretKey $sk
    ): SignedMessage {
        $self = new static($message, $recentMerkleRoot);
        $self->sign($sk);
        return $self;
    }

    public function encodeForSigning(): string
    {
        return $this->preAuthEncode([
            '!pkd-context',
            self::PKD_CONTEXT,
            'action',
            $this->message->getAction(),
            'message',
            (string) json_encode($this->message, JSON_UNESCAPED_SLASHES),
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
        } else {
            $this->signature = Base64UrlSafe::decodeNoPadding($signature);
        }
        return $key->verify($this->signature, $this->encodeForSigning());
    }

    public function toArray(): array
    {
        return [
            '!pkd-context' => self::PKD_CONTEXT,
            'action' => $this->message->getAction(),
            'message' => $this->message->toArray(),
            'recent-merkle-root' => $this->getRecentMerkleRoot(),
            'signature' => $this->getSignature(),
        ];
    }

    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
