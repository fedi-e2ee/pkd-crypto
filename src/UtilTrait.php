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

    public function stringToByteArray(string $str): array
    {
        $values = unpack('C*', $str);
        return array_values($values);
    }
}
