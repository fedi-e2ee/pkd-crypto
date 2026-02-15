<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use ParagonIE_Sodium_Core_Util;
use function array_fill,
array_key_exists,
array_slice,
array_values,
count,
is_array,
ksort,
pack,
str_repeat,
str_replace,
strlen,
unpack;

trait UtilTrait
{
    /**
     * This method throws an InputException if any of the expected keys are absent.
     * It does not return anything.
     *
     * @throws InputException
     */
    public static function assertAllArrayKeysExist(array $target, string ...$arrayKeys): void
    {
        if (!self::allArrayKeysExist($target, ...$arrayKeys)) {
            throw new InputException('All expected keys do not exist');
        }
    }

    /**
     * This method returns true if every expected array key is found in the target array.
     * Otherwise, it returns false.
     *
     * This is useful for input validation.
     */
    public static function allArrayKeysExist(array $target, string ...$arrayKeys): bool
    {
        $allExist = true;
        foreach ($arrayKeys as $arrayKey) {
            $allExist = array_key_exists($arrayKey, $target) && $allExist;
        }
        return $allExist;
    }

    /**
     * This is a constant-time conditional select. It should be read like a ternary operation.
     *
     * $result = ClassWithTrait::constantTimeSelect(1, $left, $right);
     *  -> $result === $left.
     *
     * $result = ClassWithTrait::constantTimeSelect(0, $left, $right);
     *  -> $result === $right.
     *
     * @param int $select 1 -> returns left, 0 -> returns right
     *
     * @throws CryptoException
     */
    public function constantTimeSelect(int $select, string $left, string $right): string
    {
        $len = strlen($left);
        if (strlen($right) !== $len) {
            throw new CryptoException('constantTimeSelect() expects two strings of equal length');
        }
        $cs = str_repeat('C', $len);
        // Convert to arrays of bytes
        $leftArr = $this->stringToByteArray($left);
        $rightArr = $this->stringToByteArray($right);
        $select &= 1;
        $mask = (-$select) & 0xff;

        for ($i = 0; $i < $len; ++$i) {
            $rightArr[$i] ^= ($leftArr[$i] ^ $rightArr[$i]) & $mask;
        }
        return pack($cs, ...$rightArr);
    }

    /**
     * Normalize line-endings to UNIX-style (LF rather than CRLF).
     *
     * This is mostly used for PEM-encoded strings.
     *
     * @param string $in
     * @return string
     */
    public static function dos2unix(string $in): string
    {
        return str_replace("\r\n", "\n", $in);
    }

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#preauthencode
    //# In order to canonicalize multi-part inputs to a hash function or signature algorithm, we will use the strategy from
    /**
     * This is an implementation of PAE() from PASETO. It encodes an array of strings into a flat string consisting of:
     *
     * 1. The number of pieces.
     * 2. For each piece:
     *    1. The length of the piece (in bytes).
     *    2. The contents of the piece.
     *
     * This allows multipart messages to have an injective canonical representation before passing ot a hash function
     * (or other cryptographic function).
     *
     * @param array<int, string> $pieces
     * @return string
     */
    public static function preAuthEncode(array $pieces): string
    {
        //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#preauthencode
        //# Append the LE64() of the number of pieces being encoded.
        $count = count($pieces);
        $output = self::LE64($count);
        for ($i = 0; $i < $count; ++$i) {
            //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#preauthencode
            //# Append the LE64() of the number of octets in this piece.
            $output .= self::LE64(strlen($pieces[$i]));
            $output .= $pieces[$i];
        }
        return $output;
    }

    /**
     * This sorts the target array in-place, by its keys, including child arrays.
     *
     * Used for ensuring arrays are sorted before JSON encoding.
     */
    public static function sortByKey(array &$arr): void
    {
        foreach ($arr as &$value) {
            if (is_array($value)) {
                self::sortByKey($value);
            }
        }
        ksort($arr);
    }

    //= https://raw.githubusercontent.com/fedi-e2ee/public-key-directory-specification/refs/heads/main/Specification.md#preauthencode
    //# LE64() function that accepts an unsigned 64-bit integer and returns an octet sequence in little endian byte order
    /**
     * Mostly used by preAuthEncode() above. This packs an integer as 8 bytes.
     */
    public static function LE64(int $n): string
    {
        return pack('P', $n);
    }

    /**
     * Get an array of bytes representing the input string.
     */
    public function stringToByteArray(string $str): array
    {
        $values = unpack('C*', $str);
        if ($values === false) {
            return [];
        }
        return array_values($values);
    }

    /**
     * Strip all newlines (CR, LF) characters from a string.
     *
     * @param string $input
     * @return string
     */
    public static function stripNewlines(string $input): string
    {
        $bytes = ParagonIE_Sodium_Core_Util::stringToIntArray($input);
        $length = count($bytes);

        // First value is a dummy value, to overwrite it in constant-time
        $return = array_fill(0, $length + 1, 0);
        // Output index:
        $j = 1;

        // Now let's strip:
        for ($i = 0; $i < $length; ++$i) {
            $char = ($bytes[$i]);

            // Determine if we're stripping this character or not?
            $isCR = ((($char ^ 0x0d) - 1) >> 8) & 1;
            $isLF = ((($char ^ 0x0a) - 1) >> 8) & 1;
            $isNewline = $isCR | $isLF;

            // Set destination index: 0 if $isNewLine, $j otherwise
            $swap = -$isNewline;

            // if ($isNewLine), $dest === 0, else $dest === $j
            $dest = (~$swap & $j) ^ $swap;

            // Now let's overwrite the index (0 or $j) with $char:
            $return[$dest] = $char;

            // We only advance $j if we didn't encounter a newline:
            $j += 1 - $isNewline;
        }
        return ParagonIE_Sodium_Core_Util::intArrayToString(
            array_slice($return, 1, $j - 1)
        );
    }
}
