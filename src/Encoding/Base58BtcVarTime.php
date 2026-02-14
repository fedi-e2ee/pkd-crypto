<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Encoding;

use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use ParagonIE_Sodium_Core_Util;
use function array_fill, count, floor, is_array, pack, strlen, unpack;

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
 * Despite taking pains to perform the initial leading-zero stripping in constant-time,
 * the number of leading zeroes is leaked by the iteration count of the subsequent loop.
 * When this is fully constant-time, we can remove VarTime from the class name. Until then,
 * we'll continue to be explicit about its weakened security.
 *
 * @link https://datatracker.ietf.org/doc/html/draft-msporny-base58-03
 */
class Base58BtcVarTime
{
    protected const MU = 4519;
    protected const SH = 18;

    public static function encode(string $binaryString): string
    {
        $end = strlen($binaryString);
        if ($end === 0) {
            return '';
        }

        // Avoid leaking the values of the leading bytes via cache-timing and branching:
        $bytes = ParagonIE_Sodium_Core_Util::stringToIntArray($binaryString);
        $flag = 1;
        $begin = 0;
        for ($i = 0; $i < $end; ++$i) {
            $flag = (($bytes[$i] - 1) >> 8) & $flag;
            $begin += $flag;
        }
        $zeroes = $begin;

        $expansionFactor = 1.365658237309761;
        $size = (int)floor((float)$end * $expansionFactor + 1.0);
        $baseValue = array_fill(0, $size, 0);

        $shift = (PHP_INT_SIZE << 3) - 1;
        $count = $expansionFactor + 1.0;
        for ($i = 0; $i < $end; ++$i) {
            // $mask = $i >= $begin ? 0xFF : 0;
            $mask = (($begin - $i - 1) >> $shift) & 0xff;

            $carry = $bytes[$i];
            $stop = $size - (int)floor($count);
            // $count only increases if $mask is 0xFF
            $count += $expansionFactor * (float)($mask & 1);
            for ($b = $size - 1; $stop <= $b; --$b) {
                $carry += ($baseValue[$b] << 8);
                [$div, $mod] = self::div58($carry);
                // Only update if $mask is 0xFF
                $baseValue[$b] ^= (($baseValue[$b] ^ $mod) & $mask);
                $carry = $div;
            }
        }

        $baseEncodingPosition = 0;
        $flag = 1;
        for ($i = 0; $i < $size; ++$i) {
            /** @psalm-suppress InvalidArrayOffset */
            $flag = (($baseValue[$i] - 1) >> 8) & $flag;
            $baseEncodingPosition += $flag;
        }

        $finalSize = $zeroes + ($size - $baseEncodingPosition);
        // We allocate one more byte than we need to, and then use the 0 index as a dummy value
        $encoded = array_fill(0, $finalSize + 1, 0);

        // constant-time fill of leading zeroes and the rest with 0
        for ($i = 0; $i < $finalSize; ++$i) {
            $mask = (($i - $zeroes) >> $shift); // -1 if $i < $zeroes, 0 otherwise
            $encoded[$i + 1] = (0x31 & $mask);
        }

        $j = $zeroes;
        for ($i = 0; $i < $size; ++$i) {
            $mask = (($baseEncodingPosition - $i - 1) >> $shift); // -1 if $i >= $baseEncodingPosition, 0 otherwise
            $gte = $mask & 1;
            $j += $gte;

            /** @psalm-suppress InvalidArrayOffset */
            $encodedValue = self::encodeByte($baseValue[$i]);

            // We want to write to $encoded[$j] if $mask is -1.
            // We want to write to $encoded[0] if $mask is 0.
            // The index should be ($j & $mask) | (0 & ~$mask) which is $j & $mask.
            $encoded[$j & $mask] = $encodedValue;
        }
        unset($encoded[0]);
        return ParagonIE_Sodium_Core_Util::intArrayToString($encoded);
    }

    /**
     * @throws EncodingException
     */
    public static function decode(string $encoded): string
    {
        $source = ParagonIE_Sodium_Core_Util::stringToIntArray($encoded);
        $sourceLength = count($source);

        // leading zeroes are encoded as '1' which is an ASCII char equal to 49 (0x31)
        $flag = 1;
        $acc = 0;
        for ($i = 0; $i < $sourceLength; ++$i) {
            // $flag &= (int)($flag === 0x31); without bool-to-int leakage
            $flag = ((($source[$i] ^ 0x31) - 1) >> 8) & $flag;
            $acc += $flag;
        }
        $sourceOffset = $zeroes = $acc;

        $contractionFactor = 0.7322476243909465;
        $size = (int)floor((float)$sourceLength * $contractionFactor + 1.0);
        $decodedBytes = array_fill(0, $size, 0);

        $shift = (PHP_INT_SIZE << 3) - 1;
        $error = 0;
        $count = $contractionFactor + 1.0;
        for ($i = 0; $i < $sourceLength; ++$i) {
            $mask = (($sourceOffset - $i - 1) >> $shift) & 0xff;

            $carry = self::decodeByte($source[$i]);
            $error |= ($carry >> 31) & $mask;
            $stop = $size - (int)floor($count);
            $count += $contractionFactor * (float)($mask & 1);
            for ($b = $size - 1; $stop <= $b; --$b) {
                $carry += (58 * $decodedBytes[$b]);
                $decodedBytes[$b] ^= ($decodedBytes[$b] ^ $carry) & $mask;
                $carry >>= 8;
            }
        }

        if ($error !== 0) {
            throw new EncodingException("Invalid character during decoding");
        }

        $decodedOffset = 0;
        $flag = 1;
        for ($i = 0; $i < $size; ++$i) {
            /** @psalm-suppress InvalidArrayOffset */
            $flag = (($decodedBytes[$i] - 1) >> 8) & $flag;
            $decodedOffset += $flag;
        }

        // We allocate one more byte than we need to, and then use the 0 index as a dummy value
        $finalBytes = array_fill(
            0,
            $zeroes + ($size - $decodedOffset) + 1,
            0
        );
        $j = $zeroes;
        // Iterate over the full length again, writing to [0] if outside the range of $decodedOffset..$size.
        // And then writing to [$j] (and incrementing $j) when the value is in range.
        for ($i = 0; $i < $size; ++$i) {
            $mask = (($decodedOffset - $i - 1) >> $shift); // $i >= $decodedOffset ? -1 : 0
            $gte = $mask & 1;
            $j += $gte;
            /** @psalm-suppress InvalidArrayOffset */
            $finalBytes[$j & $mask] = $decodedBytes[$i];
        }
        // delete dummy value
        unset($finalBytes[0]);
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
        $over = (57 - $r) >> 8;
        $q   -= $over;
        $r   -= $over & 58;

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

        // 'm'-'z' → 0x6D-0x7A → 44-57
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
        $unpacked = unpack('C', $chr);
        if (!is_array($unpacked)) {
            return 0;
        }
        return $unpacked[1];
    }
}
