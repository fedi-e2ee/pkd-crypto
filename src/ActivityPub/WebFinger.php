<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\ActivityPub;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NetworkException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\Certainty\Fetch;
use ParagonIE\Certainty\RemoteFetch;

class WebFinger
{
    private Client $http;

    public function __construct(?Client $client = null, ?Fetch $caCertFetcher = null)
    {
        if (is_null($client)) {
            if (is_null($caCertFetcher)) {
                $caCertFetcher = new RemoteFetch(
                    dirname(__DIR__, 2) . '/cache'
                );
            }
            $client = new Client([
                'headers' => [
                    'Accept' => 'application/jrd+json'
                ],
                'verify' => $caCertFetcher->getLatestBundle()->getFilePath()
            ]);
        }
        $this->http = $client;
    }

    /**
     * @throws NetworkException
     * @throws GuzzleException
     */
    public function canonicalize(string $actorUsernameOrUrl): string
    {
        // Is this already canonicalized?
        if (preg_match('#^https?://#i', $actorUsernameOrUrl)) {
            $url = filter_var($actorUsernameOrUrl, FILTER_VALIDATE_URL);
            if (!$url || !in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'], true)) {
                throw new NetworkException('Invalid URL provided');
            }
            // Normalize to HTTPS if possible
            return str_replace(['http://', 'HTTP://'], 'https://', $url);
        }
        $actorUsernameOrUrl = ltrim($actorUsernameOrUrl, '@');
        if (!str_contains($actorUsernameOrUrl, '@')) {
            throw new NetworkException('Actor handle must contain exactly one @');
        }
        [$username, $domain] = explode('@', $actorUsernameOrUrl, 2);
        if (empty($username) || empty($domain)) {
            throw new \InvalidArgumentException('Invalid actor handle format');
        }

        // Optional: Support internationalized domain names
        if (extension_loaded('intl')) {
            $domain = idn_to_ascii($domain, IDNA_DEFAULT) ?? $domain;
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
            return $link->href;
        }
        throw new NetworkException('No canonical URL found for ' . $actorUsernameOrUrl);
    }
}
