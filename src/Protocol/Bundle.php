<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\SymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;

class Bundle
{
    private string $pkdContext = 'https://github.com/fedi-e2ee/public-key-directory/v1';
    private string $action;
    private array $message;
    private string $recentMerkleRoot;
    private string $signature;
    private AttributeKeyMap $symmetricKeys;

    public function __construct(
        string $action,
        array $message,
        string $recentMerkleRoot,
        string $signature,
        AttributeKeyMap $symmetricKeys
    ) {
        $this->action = $action;
        $this->message = $message;
        $this->recentMerkleRoot = $recentMerkleRoot;
        $this->signature = $signature;
        $this->symmetricKeys = $symmetricKeys;
    }

    public static function fromJson(string $json): self
    {
        if (empty($json)) {
            throw new \Exception('Empty JSON string');
        }
        $data = json_decode($json, true);
        if (is_null($data)) {
            throw new \Exception('Invalid JSON string');
        }
        $symmetricKeys = new AttributeKeyMap();
        foreach ($data['symmetric-keys'] as $attribute => $key) {
            $symmetricKeys->addKey($attribute, new SymmetricKey(Base64UrlSafe::decode($key)));
        }

        return new self(
            $data['action'],
            $data['message'],
            Base64UrlSafe::decode($data['recent-merkle-root']),
            Base64UrlSafe::decode($data['signature']),
            $symmetricKeys
        );
    }

    public function toJson(): string
    {
        $symmetricKeys = [];
        foreach ($this->symmetricKeys->getAttributes() as $attribute) {
            $key = $this->symmetricKeys->getKey($attribute);
            if ($key) {
                $symmetricKeys[$attribute] = Base64UrlSafe::encode($key->getBytes());
            }
        }

        return json_encode([
            '!pkd-context' => $this->pkdContext,
            'action' => $this->action,
            'message' => $this->message,
            'recent-merkle-root' => Base64UrlSafe::encode($this->recentMerkleRoot),
            'signature' => Base64UrlSafe::encode($this->signature),
            'symmetric-keys' => $symmetricKeys,
        ], JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '';
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
}
