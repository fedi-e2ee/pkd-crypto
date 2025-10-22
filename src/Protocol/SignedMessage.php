<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

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

    public function encodeForSigning(): string
    {
        return $this->preAuthEncode(array_values([
            '!pkd-context',
            self::PKD_CONTEXT,
            'action',
            $this->message->getAction(),
            'message',
            json_encode($this->message, JSON_UNESCAPED_SLASHES),
            'recent-merkle-root',
            $this->recentMerkleRoot
        ]));
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
            'message' => json_encode($this->message, JSON_UNESCAPED_SLASHES),
            'recent-merkle-root' => $this->recentMerkleRoot,
            'signature' => $this->signature,
        ];
    }

    #[Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
