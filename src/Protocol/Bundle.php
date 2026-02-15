<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Protocol;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    BundleException,
    CryptoException,
    InputException,
    JsonException,
    NetworkException
};
use FediE2EE\PKD\Crypto\{
    SymmetricKey,
    UtilTrait
};
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function in_array, is_array, is_null, is_string, json_decode, json_encode, json_last_error, json_last_error_msg;

class Bundle
{
    use UtilTrait;

    public function __construct(
        private readonly string          $action,
        private readonly array           $message,
        private readonly string          $recentMerkleRoot,
        private readonly string          $signature,
        private readonly AttributeKeyMap $symmetricKeys,
        private readonly string          $pkdContext = 'https://github.com/fedi-e2ee/public-key-directory/v1',
        private readonly ?string         $otp = null,
        private readonly ?string         $revocationToken = null,
    ) {}

    /**
     * @throws BundleException
     * @throws CryptoException
     * @throws InputException
     */
    public static function fromJson(string $json, ?AttributeKeyMap $symmetricKeys = null): self
    {
        if (empty($json)) {
            throw new BundleException('Empty JSON string');
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new BundleException('Invalid JSON string: ' . json_last_error_msg());
        }
        self::assertAllArrayKeysExist($data, 'action');

        if ($data['action'] === 'RevokeKeyThirdParty') {
            self::assertAllArrayKeysExist($data, 'revocation-token');
            return new self(
                action: $data['action'],
                message: [],
                recentMerkleRoot: '',
                signature: '',
                symmetricKeys: new AttributeKeyMap(),
                revocationToken: $data['revocation-token'],
            );
        }

        if (is_null($symmetricKeys)) {
            self::assertAllArrayKeysExist(
                $data,
                'symmetric-keys',
                'message',
                'recent-merkle-root',
                // We do not always have a "signature" field, so it is omitted here.
            );
            if (!is_array($data['symmetric-keys'])) {
                throw new BundleException('symmetric-keys must be an array');
            }
            $symmetricKeys = new AttributeKeyMap();
            foreach ($data['symmetric-keys'] as $attribute => $key) {
                if (!is_string($key)) {
                    throw new BundleException('Each symmetric-key must be a string');
                }
                $symmetricKeys->addKey(
                    $attribute,
                    new SymmetricKey(
                        Base64UrlSafe::decodeNoPadding($key)
                    )
                );
            }
        } else {
            self::assertAllArrayKeysExist(
                $data,
                'message',
                'recent-merkle-root',
                // We do not always have a "signature" field. Omission is deliberate.
            );
        }

        // BurnDown has otp at the top level (not in the message map).
        $otp = null;
        if ($data['action'] === 'BurnDown') {
            $otp = $data['otp'] ?? null;
        }

        return new self(
            $data['action'],
            $data['message'],
            $data['recent-merkle-root'],
            Base64UrlSafe::decodeNoPadding($data['signature']),
            $symmetricKeys,
            otp: $otp,
        );
    }

    /**
     * @throws JsonException
     */
    public function toJson(): string
    {
        $flags = JSON_PRESERVE_ZERO_FRACTION
            | JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE;

        // RevokeKeyThirdParty has a minimal structure.
        if ($this->action === 'RevokeKeyThirdParty') {
            $data = [
                'action' => $this->action,
                'revocation-token' => $this->revocationToken,
            ];
            ksort($data);
            $encoded = json_encode($data, $flags);
            if (!is_string($encoded)) {
                throw new JsonException(
                    json_last_error_msg(),
                    json_last_error()
                );
            }
            return $encoded;
        }

        $symmetricKeys = [];
        foreach ($this->symmetricKeys->getAttributes() as $attribute) {
            $key = $this->symmetricKeys->getKey($attribute);
            if ($key) {
                $symmetricKeys[$attribute] = Base64UrlSafe::encodeUnpadded(
                    $key->getBytes()
                );
            }
        }

        $data = [
            '!pkd-context' => $this->pkdContext,
            'action' => $this->action,
            'message' => $this->message,
            'recent-merkle-root' => $this->recentMerkleRoot,
            'signature' =>
                Base64UrlSafe::encodeUnpadded($this->signature),
            'symmetric-keys' => $symmetricKeys,
        ];
        if ($this->otp !== null) {
            $data['otp'] = $this->otp;
        }

        ksort($data);
        $encoded = json_encode($data, $flags);
        if (!is_string($encoded)) {
            throw new JsonException(
                json_last_error_msg(),
                json_last_error()
            );
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

    public function getOtp(): ?string
    {
        return $this->otp;
    }

    public function getRevocationToken(): ?string
    {
        return $this->revocationToken;
    }

    /**
     * @throws CryptoException
     * @throws GuzzleException
     * @throws InputException
     * @throws JsonException
     * @throws NetworkException
     */
    public function toSignedMessage(): SignedMessage
    {
        $parser = new Parser();
        if (in_array($this->getAction(), Parser::PLAINTEXT_ACTIONS, true)) {
            $message = $parser->getUnencryptedMessage($this);
        } else {
            $message = $parser->getEncryptedMessage($this);
        }

        return new SignedMessage(
            $message,
            $this->getRecentMerkleRoot(),
            $this->signature
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
