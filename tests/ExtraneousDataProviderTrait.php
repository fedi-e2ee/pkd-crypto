<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Enums\ProtocolVersion;
use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;

trait ExtraneousDataProviderTrait
{
    /**
     * @return SigningAlgorithm[][]
     */
    public static function protocolVersionsProvider(): array
    {
        return [
            [ProtocolVersion::V1],
        ];
    }

    /**
     * @return SigningAlgorithm[][]
     */
    public static function signingAlgorithmProvider(): array
    {
        return [
            [SigningAlgorithm::ED25519],
            [SigningAlgorithm::MLDSA44],
        ];
    }

    /**
     * @return SigningAlgorithm[][]
     */
    public static function signingAlgorithmProviderFast(): array
    {
        $cases = [[SigningAlgorithm::ED25519]];
        if (extension_loaded('pqcrypto')) {
            $cases[] = [SigningAlgorithm::MLDSA44];
        }
        return $cases;
    }

    /**
     * @return SigningAlgorithm[][]
     */
    public static function ed25519OnlyProvider(): array
    {
        return [
            [SigningAlgorithm::ED25519],
        ];
    }

    /**
     * @return SigningAlgorithm[][]
     */
    public static function pkdAllowedSigningAlgorithmProvider(): array
    {
        return [
            [SigningAlgorithm::MLDSA44],
        ];
    }
}
