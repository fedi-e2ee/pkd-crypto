<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto;

use FediE2EE\PKD\Crypto\Exceptions\{CryptoException, HttpSignatureException, NotImplementedException};
use ParagonIE\ConstantTime\Base64;
use Psr\Http\Message\{
    MessageInterface,
    RequestInterface
};
use SodiumException;

/**
 * @api
 */
final class HttpSignature
{
    private string $label;
    private int $timeoutWindow;

    /**
     * @throws HttpSignatureException
     */
    public function __construct(string $label = 'sig1', int $timeoutWindow = 300)
    {
        if ($timeoutWindow < 2 || $timeoutWindow > 86400) {
            throw new HttpSignatureException('Invalid timeout window size: ' . $timeoutWindow);
        }
        $this->label = $label;
        $this->timeoutWindow = $timeoutWindow;
    }

    /**
     * @throws NotImplementedException
     * @throws SodiumException
     *
     * @psalm-suppress UnusedVariable
     */
    public function sign(
        SecretKey $secretKey,
        MessageInterface $message,
        array $headersToSign = [],
        string $keyId = '',
        ?int $created = null
    ): MessageInterface {
        if (is_null($created)) {
            // Default to the current time
            $created = time();
        }
        $signatureInput = $this->buildSignatureInput(
            $this->label,
            $headersToSign,
            $keyId,
            $created
        );
        $signatureBase = $this->getSignatureBase($message, $headersToSign, $signatureInput);
        $signature = $secretKey->sign($signatureBase);
        return $message
            ->withHeader('Signature-Input', $signatureInput)
            ->withHeader('Signature', $this->label . '=:' . Base64::encode($signature) . ':');
    }

    /**
     * @throws NotImplementedException
     * @throws HttpSignatureException
     * @throws SodiumException
     */
    public function verify(
        PublicKey $publicKey,
        MessageInterface $message
    ): bool {
        if (!$message->hasHeader('Signature-Input') || !$message->hasHeader('Signature')) {
            return false;
        }
        $signatureInput = $message->getHeaderLine('Signature-Input');
        $signatureHeader = $message->getHeaderLine('Signature');
        ['coveredComponents' => $headersToSign, 'params' => $params] = $this->parseSignatureInput($signatureInput);

        if (!isset($params['alg']) || $params['alg'] !== '"ed25519"') {
            return false;
        }
        if (!isset($params['created']) || !is_numeric($params['created'])) {
            return false;
        }
        if (abs(time() - (int) $params['created']) > $this->timeoutWindow) {
            return false;
        }

        $signatureBase = $this->getSignatureBase($message, $headersToSign, $signatureInput);
        $label = preg_quote($this->label, '/');
        preg_match('/' . $label . '=:([^:]+):/', $signatureHeader, $matches);
        if (!isset($matches[1])) {
            return false;
        }
        $signature = Base64::decode($matches[1]);
        return $publicKey->verify($signature, $signatureBase);
    }

    /**
     * @param MessageInterface $message
     * @param array<int, string> $headersToSign
     * @param string $signatureInput
     * @return string
     */
    private function getSignatureBase(
        MessageInterface $message,
        array $headersToSign,
        string $signatureInput
    ): string {
        $lines = [];
        foreach ($headersToSign as $header) {
            $header = strtolower($header);
            if ($header === '@method') {
                if ($message instanceof RequestInterface) {
                    $lines[] = "\"@method\": " . strtolower($message->getMethod());
                }
                continue;
            }
            if ($header === '@path') {
                if ($message instanceof RequestInterface) {
                    $lines[] = "\"@path\": " . $message->getUri()->getPath();
                }
                continue;
            }
            if ($message->hasHeader($header)) {
                $lines[] = "\"$header\": " . $message->getHeaderLine($header);
            }
        }
        $lines[] = '"@signature-params": ' . $this->getSignatureParamsForBase($signatureInput);

        return implode("\n", $lines);
    }

    private function getSignatureParamsForBase(string $signatureInput): string
    {
        preg_match('/^[^=]+=(.*)$/', $signatureInput, $matches);
        return $matches[1] ?? '';
    }


    /**
     * @param string $label
     * @param array<int, string> $headersToSign
     * @param string $keyId
     * @param int $created
     * @return string
     */
    private function buildSignatureInput(
        string $label,
        array $headersToSign,
        string $keyId,
        int $created
    ): string {
        $covered = implode(' ', array_map(fn($h) => '"' . strtolower($h) . '"', $headersToSign));
        $params = [
            'alg="ed25519"',
            'keyid="' . $keyId . '"',
            'created=' . $created,
        ];
        return "$label=($covered);" . implode(';', $params);
    }

    /**
     * @param string $header
     * @return array{coveredComponents: array<string>, params: array<string, string>}
     * @throws HttpSignatureException
     */
    private function parseSignatureInput(string $header): array
    {
        if (!preg_match('/^([^=]+)=\(([^)]+)\)(.*)$/', $header, $matches)) {
            throw new HttpSignatureException('Invalid signature header');
        }

        $coveredComponentsStr = $matches[2];
        $paramsStr = $matches[3];

        $coveredComponents = [];
        if (preg_match_all('/"([^"]+)"/', $coveredComponentsStr, $componentMatches)) {
            $coveredComponents = $componentMatches[1];
        }

        $params = [];
        if (preg_match_all('/;([^=]+)=("([^"]+)"|([0-9]+))/', $paramsStr, $paramMatches, PREG_SET_ORDER)) {
            foreach ($paramMatches as $match) {
                $params[$match[1]] = $match[2];
            }
        }

        return [
            'coveredComponents' => $coveredComponents,
            'params' => $params,
        ];
    }
}
