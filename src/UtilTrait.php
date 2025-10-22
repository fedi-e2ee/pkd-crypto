<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;

trait UtilTrait
{
    /**
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
     * @param array<int, string> $pieces
     * @return string
     */
    public function preAuthEncode(array $pieces): string
    {
        $count = count($pieces);
        $output = self::LE64($count);
        for ($i = 0; $i < $count; ++$i) {
            $output .= self::LE64(strlen($pieces[$i]));
            $output .= $pieces[$i];
        }
        return $output;
    }

    public static function sortByKey(array &$arr): void
    {
        foreach ($arr as &$value) {
            if (is_array($value)) {
                self::sortByKey($value);
            }
        }
        ksort($arr);
    }

    public static function LE64(int $n): string
    {
        return pack('P', $n);
    }

    public function stringToByteArray(string $str): array
    {
        $values = unpack('C*', $str);
        return array_values($values);
    }
}
