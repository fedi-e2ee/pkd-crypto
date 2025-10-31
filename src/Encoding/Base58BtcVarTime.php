<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Encoding;

use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use ParagonIE_Sodium_Core_Util;

/**
 * Variable-time base58 codec.
 *
 * This is NOT constant-time. If you use it for private keys, you will have a bad time!
 *
 * The main timing leak is caused by the handling of leading zeroes. We manage to avoid:
 *
 * 1. Branching-based timing leaks (via avoiding branches).
 * 2. Division-based timing leaks (via Barrett Reduction).
 * 3. Cache-timing leaks (via replacing the table look-up with bit-twiddling).
 *
 * @link https://datatracker.ietf.org/doc/html/draft-msporny-base58-03
 */
class Base58BtcVarTime
{
    protected const MU = 18512791;
    protected const SH = 30;

    public static function encode(string $binaryString): string
    {
        $zeroes = 0;
        $length = 0;
        $begin = 0;
        $end = strlen($binaryString);
        if ($end === 0) {
            return '';
        }

        $bytes = ParagonIE_Sodium_Core_Util::stringToIntArray($binaryString);
        while ($begin !== $end && $bytes[$begin] === 0) {
            ++$begin;
            ++$zeroes;
        }

        $expansionFactor = 1.365658237309761;
        $size = (int)floor(($end - $begin) * $expansionFactor + 1);
        $baseValue = array_fill(0, $size, 0);

        while ($begin !== $end) {
            $carry = $bytes[$begin];
            $i = 0;
            for (
                $basePosition = $size - 1;
                ($carry !== 0 || $i < $length) && ($basePosition !== -1);
                --$basePosition, ++$i
            ) {;
                $carry += $baseValue[$basePosition] << 8;
                [$div, $mod] = self::div58($carry);
                if ($div > 255 || $mod > 255) {
                    exit;
                }
                $baseValue[$basePosition] = $mod;
                $carry = $div;
            }

            $length = $i;
            ++$begin;
        }

        $baseEncodingPosition = $size - $length;
        /** @psalm-suppress InvalidArrayOffset */
        while ($baseEncodingPosition !== $size && $baseValue[$baseEncodingPosition] === 0) {
            ++$baseEncodingPosition;
        }

        $encoded = array_fill(0, $zeroes, 0x31);
        for (; $baseEncodingPosition < $size; ++$baseEncodingPosition) {
            /** @psalm-suppress InvalidArrayOffset */
            $encoded []= self::encodeByte($baseValue[$baseEncodingPosition]);
        }
        return ParagonIE_Sodium_Core_Util::intArrayToString($encoded);
    }

    /**
     * @throws EncodingException
     */
    public static function decode(string $encoded): string
    {
        $source = ParagonIE_Sodium_Core_Util::stringToIntArray($encoded);
        $sourceLength = count($source);
        $sourceOffset = 0;
        $zeroes = 0;
        $decodedLength = 0;

        // leading zeroes are encoded as '1' which is an ASCII char equal to 49 (0x31)
        while ($source[$sourceOffset] === 0x31) {
            ++$sourceOffset;
            ++$zeroes;
        }

        $contractionFactor = 0.7322476243909465;
        $size = (int)floor(($sourceLength - $sourceOffset) * $contractionFactor + 1);
        $decodedBytes = array_fill(0, $size, 0);

        $error = 0;
        while ($sourceOffset < $sourceLength) {
            $carry = self::decodeByte($source[$sourceOffset]);
            $error |= $carry >> 31;

            $i = 0;
            for (
                $byteOffset = $size - 1;
                ($carry !== 0 || $i < $decodedLength) && ($byteOffset !== -1);
                --$byteOffset, ++$i) {
                $carry += (58 * $decodedBytes[$byteOffset]);
                $decodedBytes[$byteOffset] = $carry & 0xff;
                $carry >>= 8;
            }

            $decodedLength = $i;
            ++$sourceOffset;
        }

        if ($error !== 0) {
            throw new EncodingException("Invalid character during decoding");
        }

        $decodedOffset = $size - $decodedLength;
        /** @psalm-suppress InvalidArrayOffset */
        while ($decodedOffset !== $size && $decodedBytes[$decodedOffset] === 0) {
            ++$decodedOffset;
        }

        $finalBytes = array_fill(
            0,
            $zeroes + ($size - $decodedOffset),
            0
        );
        $j = $zeroes;
        while ($decodedOffset !== $size) {
            /** @psalm-suppress InvalidArrayOffset */
            $finalBytes[$j++] = $decodedBytes[$decodedOffset++];
        }
        return ParagonIE_Sodium_Core_Util::intArrayToString($finalBytes);
    }

    /**
     * Returns (x / 58, x % 58), using Barrett Reduction.
     * @return int[]
     */
    public static function div58(int $x): array
    {
        $prod = self::MU * $x;
        $q    = $prod >> self::SH;
        $r    = $x - $q * 58;

        return [$q, $r];
    }

    /**
     * Convert a value in [0, 57] to a corresponding ASCII character index.
     */
    public static function encodeByte(int $input): int
    {
        $diff = 0x31;

        // if ($input > 8) $diff += (0x38 - 0x31); // 7
        $diff += ((8 - $input) >> 8) & 7;

        // if (input > 16) $diff++;
        $diff += ((16 - $input) >> 8) & 1;

        // if ($input > 21) $diff++;
        $diff += ((21 - $input) >> 8) & 1;

        // if ($input > 32) $diff += (0x40 - 0x3a); // 6
        $diff += ((32 - $input) >> 8) & 6;

        // if ($input > 43) $diff++;
        $diff += ((43 - $input) >> 8) & 1;

        return $input + $diff;
    }

    /**
     * Convert an ASCII value to the corresponding index, based on the alphabet.
     *
     * Returns an integer between 0 and 57 on success.
     * Returns -1 on error.
     */
    public static function decodeByte(int $input): int
    {
        $ret = -1;

        // '1'-'9' → 0x31-0x39 → 0-8
        $ret += (((0x30 - $input) & ($input - 0x3A)) >> 8) & ($input - 0x30);

        // 'A'-'H' → 0x41-0x48 → 9-16
        $ret += (((0x40 - $input) & ($input - 0x49)) >> 8) & ($input - 0x37);

        // 'J'-'N' → 0x4A-0x4E → 17-21
        $ret += (((0x49 - $input) & ($input - 0x4F)) >> 8) & ($input - 0x38);

        // 'P'-'Z' → 0x50-0x5A → 22-32
        $ret += (((0x4F - $input) & ($input - 0x5B)) >> 8) & ($input - 0x39);

        // 'a'-'k' → 0x61-0x6B → 33-43
        $ret += (((0x60 - $input) & ($input - 0x6C)) >> 8) & ($input - 0x3F);

        // 'l'-'z' → 0x6D-0x7A → 44-57
        $ret += (((0x6C - $input) & ($input - 0x7B)) >> 8) & ($input - 0x40);

        return $ret;
    }

    /**
     * Avoid cache-timing leaks in chr() by using pack()
     */
    protected static function chr(int $num): string
    {
        return pack('C', $num);
    }

    /**
     * Avoid cache-timing leaks in ord() by using unpack()
     */
    protected static function ord(string $chr): int
    {
        return unpack('C', $chr)[1];
    }
}
