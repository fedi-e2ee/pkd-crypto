<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\ActivityPub;

use FediE2EE\PKD\Crypto\Exceptions\{
    InputException,
    JsonException,
    NetworkException
};
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\Certainty\{
    Exception\CertaintyException,
    Fetch,
    RemoteFetch
};
use SodiumException;
use function
    array_key_exists,
    dirname,
    explode,
    extension_loaded,
    filter_var,
    http_build_query,
    in_array,
    is_array,
    is_null,
    is_object,
    json_decode,
    json_last_error_msg,
    ltrim,
    parse_url,
    preg_match,
    property_exists,
    str_contains,
    str_replace;

class WebFinger
{
    protected Client $http;
    protected Fetch $caCertFetcher;
    protected array $webFingerCache = [];

    /**
     * @throws CertaintyException
     * @throws SodiumException
     */
    public function __construct(?Client $client = null, ?Fetch $caCertFetcher = null)
    {
        if (is_null($caCertFetcher)) {
            $caCertFetcher = new RemoteFetch(
                dirname(__DIR__, 2) . '/cache'
            );
        }
        $this->caCertFetcher = $caCertFetcher;
        if (is_null($client)) {
            $client = new Client([
                'headers' => [
                    'Accept' => 'application/jrd+json'
                ],
                'verify' => $this->caCertFetcher->getLatestBundle()->getFilePath(),
                'timeout' => 10.0,
                'connect_timeout' => 5.0
            ]);
        }
        $this->http = $client;
    }

    public function getCaCertFetcher(): Fetch
    {
        return $this->caCertFetcher;
    }

    /**
     * Canonicalize an ActivityPub user handle (@user@domain or user@domain) into the Actor ID
     * (e.g., https://domain/users/username)
     *
     * @throws InputException
     * @throws NetworkException
     * @throws GuzzleException
     * @throws JsonException
     */
    public function canonicalize(string $actorUsernameOrUrl): string
    {
        if (array_key_exists($actorUsernameOrUrl, $this->webFingerCache)) {
            return $this->webFingerCache[$actorUsernameOrUrl];
        }
        // Is this already canonicalized?
        if (preg_match('#^https?://([^/]+)/(.+?)$#i', $actorUsernameOrUrl, $m)) {
            $url = filter_var($actorUsernameOrUrl, FILTER_VALIDATE_URL);
            if (!$url || !in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'], true)) {
                throw new NetworkException('Invalid URL provided');
            }
            if (str_contains($m[1], '://')) {
                throw new InputException('Parse error: URL contains :// after protocol');
            }
            if (str_contains($m[2], '://')) {
                throw new InputException('Parse error: URL contains :// after domain');
            }
            // Normalize to HTTPS if possible
            return str_replace(['http://', 'HTTP://'], 'https://', $url);
        }
        $actorUsernameOrUrl = ltrim($actorUsernameOrUrl, '@');
        if (!str_contains($actorUsernameOrUrl, '@')) {
            throw new InputException('Actor handle must contain exactly one @');
        }
        $parts = explode('@', $actorUsernameOrUrl, 2);
        $username = $parts[0];
        $domain = $parts[1] ?? '';
        if (empty($username) || empty($domain)) {
            throw new InputException('Invalid actor handle format');
        }
        if (str_contains($domain, '@')) {
            throw new InputException('Parse error: domain contains @');
        }
        if (str_contains($username, '://')) {
            throw new InputException('Parse error: username contains ://');
        }

        // Optional: Support internationalized domain names
        if (extension_loaded('intl')) {
            $asciiDomain = idn_to_ascii($domain);
            $domain = $asciiDomain !== false ? $asciiDomain : $domain;
        }
        $url = 'https://' . $domain . '/.well-known/webfinger?' . http_build_query([
            'resource' => 'acct:' . $username . '@' . $domain
        ]);
        $response = $this->http->get($url);
        $body = (string) $response->getBody();
        $data = json_decode($body);
        if (!is_object($data)) {
            throw new JsonException('Invalid JSON in WebFinger response:' . json_last_error_msg());
        }
        if (!property_exists($data, 'links') || !is_array($data->links)) {
            throw new NetworkException('WebFinger response missing "links" array');
        }
        foreach ($data->links as $link) {
            if (!property_exists($link, 'rel')
                || !property_exists($link, 'type')
                || !property_exists($link, 'href')) {
                continue;
            }
            if ($link->rel !== 'self') {
                continue;
            }
            if ($link->type !== 'application/activity+json') {
                continue;
            }
            if (!filter_var($link->href, FILTER_VALIDATE_URL)) {
                continue;
            }
            $this->webFingerCache[$actorUsernameOrUrl] = $link->href;
            return $link->href;
        }
        throw new NetworkException('No canonical URL found for ' . $actorUsernameOrUrl);
    }

    public function clearWebFingerCache(): void
    {
        $this->webFingerCache = [];
    }
}
