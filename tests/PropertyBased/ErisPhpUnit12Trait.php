<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\PropertyBased;

/**
 * PHPUnit 12 compatibility trait for Eris property-based testing.
 *
 * PHPUnit 12 removed support for @before annotations and the
 * parseTestMethodAnnotations() method that Eris relies on.
 * This trait provides the necessary compatibility workarounds.
 */
trait ErisPhpUnit12Trait
{
    /**
     * Initialize Eris for PHPUnit 12.
     *
     * Call this from setUp() after parent::setUp().
     */
    private function erisSetupCompat(): void
    {
        $seed = (int) (getenv('ERIS_SEED') ?: random_int(0, PHP_INT_MAX));
        if ($seed < 0) {
            $seed *= -1;
        }
        $this->seed = $seed;
        $this->withRand('mt_rand');
    }

    /**
     * Override to return empty annotations.
     *
     * PHPUnit 12 removed parseTestMethodAnnotations(), so we return
     * an empty structure to satisfy Eris's getTestCaseAnnotations().
     */
    public function getTestCaseAnnotations(): array
    {
        return ['method' => [], 'class' => []];
    }
}
