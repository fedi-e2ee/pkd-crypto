<?php
declare(strict_types=1);

namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Enums\ProtocolVersion;
use FediE2EE\PKD\Crypto\Enums\SigningAlgorithm;

trait ExtraneousDataProviderTrait
{
    public static function protocolVersionsProvider(): array
    {
        return [
            [ProtocolVersion::V1],
        ];
    }

    public static function signingAlgorithmProvider(): array
    {
        return [
            [SigningAlgorithm::ED25519],
            [SigningAlgorithm::MLDSA44],
        ];
    }

    public static function pkdAllowedSigningAlgorithmProvider(): array
    {
        return [
            [SigningAlgorithm::MLDSA44],
        ];
    }
}
