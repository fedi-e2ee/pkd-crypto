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
