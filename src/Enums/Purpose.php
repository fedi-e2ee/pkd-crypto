<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Enums;

enum Purpose: string
{
    case HTTP_SIGNATURES = 'http-signatures';
    case PUBLIC_KEY_DIRECTORY = 'public-key-directory';
}
