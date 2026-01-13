# Using This Library

## Easy Mode - Protocol Handler

First, you need to instantiate a Protocol Message, as well as a mapping of which symmetric key to use to encrypt each
field.

Here's an example of an AddKey message.

```php
<?php
use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Protocol\Actions\AddKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Crypto\SymmetricKey;

// Generate a keypair
$secretKey = SecretKey::generate();
$publicKey = $secretKey->getPublicKey();

// Create an inaugural AddKey message
$message = new AddKey(
    actor: "https://example.com/@actor",
    publicKey: $publicKey
);

// Map attributes to randomly-generated keys:
$keyMap = (new AttributeKeyMap())
    ->addKey('actor', SymmetricKey::generate())
    ->addKey('public-key', SymmetricKey::generate());
```

You'll need to grab the HPKE `EncapsKey` from the Public key Directory Server, as well as a recent Merkle Root.

```php
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\KEM\DHKEM\{
    Curve,
    EncapsKey
};

$valueFromServer = ""; /* ... grab from server ... */
$serverEncapsKey = new EncapsKey(Curve::X25519, Base64UrlSafe::decodeNoPadding($valueFromServer));
$recentMerkleRoot = ""; /* ... grab from server ... */
```

Finally, call the Protocol Handler, like so:

```php
<?php
use ParagonIE\HPKE\Factory;
use FediE2EE\PKD\Crypto\Protocol\Handler;

$handler = new Handler();
$bundle = $handler->handle($message, $secretKey, $keyMap, $reecentMerkleRoot);

// HPKE encryption
$hpke = Factory::init('DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305');
$encrypted = $handler->hpkeEncrypt($bundle, $encapsKey, $hpke);
```

### What Is This Doing Under The Hood?

First, it encrypts each attribute with the symmetric key mapped to it.

Then, it signs the bundle of attributes (some which may be encrypted).

Next, it takes the signed attributes and symmetric keys, and serializes it as a JSON blob called a "Bundle".

Finally, it uses an HPKE library to encrypt the bundle into a Base64url-encoded binary blob. You can toss this blob
at the server and it will be decrypted.

## Easy Mode - Protocol Parser

To decrypt and parse an encrypted message, you will need the `DecapsKey` that corresponds to the `EncapsKey` that was
used to encrypt the message.

```php
<?php
use FediE2EE\PKD\Crypto\Protocol\Parser;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\Interfaces\DecapsKeyInterface;
use FediE2EE\PKD\Crypto\PublicKey;

$parser = new Parser();
/**
 * @var HPKE $hpke                     HPKE container object; defines a ciphersuite
 * @var DecapsKeyInterface $decapsKey  Decapsulation Key; used to decrypt messages
 * @var PublicKey $publicKey           Public key used to verify the protocol message.
 */

$parsed = $parser->decryptAndParse($encrypted, $decapsKey, $hpke, $publicKey);

// You can now use these
$keyMap = $parsed->getKeyMap();
$message = $parsed->getMessage();
```

## Sharp Edges

This library was designed to be used for the Public Key Directory and is not a general purpose cryptography library.
The API contains multiple sharp edges that developers need to be aware of to use safely.

### Attribute Encryption is Optional

If a field was omitted from `AttributeKeyMap`, calling `encrypt()` on any protocol action results in plaintext being
silently transmitted. This is because attribute encryption is **optional** and only intended to enable crypto-shredding
as part of "not making GDPR compliance logically impossible".

### HTTP Signature Verification Doesn't Distinguish Cause

The verify() method just returns `false` instead of throwing a specific Exception.
