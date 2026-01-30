<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Encoding;

use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function strlen, substr;

class Multibase
{
    public static function decode(string $encoded): string
    {
        if (strlen($encoded) < 1) {
            throw new EncodingException('Multibase encoding requires a header');
        }
        $header = $encoded[0];
        return match ($header) {
            'u' => Base64UrlSafe::decode(substr($encoded, 1)),
            'z' => Base58BtcVarTime::decode(substr($encoded, 1)),
            default => throw new EncodingException('Unknown header: ' . $header),
        };
    }

    public static function encode(string $binary, bool $useUnsafe = false): string
    {
        if ($useUnsafe) {
            return 'z' . Base58BtcVarTime::encode($binary);
        }
        return 'u' . Base64UrlSafe::encodeUnpadded($binary);
    }
}
