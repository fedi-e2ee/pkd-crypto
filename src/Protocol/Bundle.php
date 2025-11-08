<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\BundleException;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;

class Bundle
{
    public function __construct(
        private readonly string          $action,
        private readonly array           $message,
        private readonly string          $recentMerkleRoot,
        private readonly string          $signature,
        private readonly AttributeKeyMap $symmetricKeys,
        private readonly string          $pkdContext = 'https://github.com/fedi-e2ee/public-key-directory/v1'
    ) {}

    /**
     * @throws BundleException
     */
    public static function fromJson(string $json): self
    {
        if (empty($json)) {
            throw new BundleException('Empty JSON string');
        }
        $data = json_decode($json, true);
        if (is_null($data)) {
            throw new  BundleException('Invalid JSON string');
        }
        $symmetricKeys = new AttributeKeyMap();
        foreach ($data['symmetric-keys'] as $attribute => $key) {
            $symmetricKeys->addKey(
                $attribute,
                new SymmetricKey(
                    Base64UrlSafe::decodeNoPadding($key)
                )
            );
        }

        return new self(
            $data['action'],
            $data['message'],
            Base64UrlSafe::decodeNoPadding($data['recent-merkle-root']),
            Base64UrlSafe::decodeNoPadding($data['signature']),
            $symmetricKeys
        );
    }

    /**
     * @throws JsonException
     */
    public function toJson(): string
    {
        $symmetricKeys = [];
        foreach ($this->symmetricKeys->getAttributes() as $attribute) {
            $key = $this->symmetricKeys->getKey($attribute);
            if ($key) {
                $symmetricKeys[$attribute] = Base64UrlSafe::encodeUnpadded(
                    $key->getBytes()
                );
            }
        }

        $flags = JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $encoded = json_encode([
            '!pkd-context' =>
                $this->pkdContext,
            'action' =>
                $this->action,
            'message' =>
                $this->message,
            'recent-merkle-root' =>
                Base64UrlSafe::encodeUnpadded($this->recentMerkleRoot),
            'signature' =>
                Base64UrlSafe::encodeUnpadded($this->signature),
            'symmetric-keys' =>
                $symmetricKeys,
        ], $flags);
        if (!is_string($encoded)) {
            throw new JsonException(json_last_error_msg(), json_last_error());
        }
        return $encoded;
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function getMessage(): array
    {
        return $this->message;
    }

    public function getRecentMerkleRoot(): string
    {
        return $this->recentMerkleRoot;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function getSymmetricKeys(): AttributeKeyMap
    {
        return $this->symmetricKeys;
    }

    /**
     * @throws CryptoException
     */
    public function toSignedMessage(): SignedMessage
    {
        $parser = new Parser();
        if (in_array($this->getAction(), Parser::UNENCRYPTED_ACTIONS, true)) {
            $message = $parser->getUnencryptedMessage($this);
        } else {
            $message = $parser->getEncryptedMessage($this);
        }

        return new SignedMessage(
            $message,
            $this->getRecentMerkleRoot(),
            Base64UrlSafe::decodeNoPadding($this->getSignature())
        );
    }

    /**
     * @throws JsonException
     */
    public function toString(): string
    {
        return $this->toJson();
    }

    /**
     * @throws JsonException
     */
    public function __toString(): string
    {
        return $this->toJson();
    }
}
