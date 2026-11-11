<?php

declare(strict_types=1);

namespace Mailcow\Scim\Controller;

use Mailcow\Scim\Model\Filter;
use Mailcow\Scim\Model\Response;
use Mailcow\Scim\Model\Schema;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\ScimError;
use Mailcow\Scim\Service\GroupService;
use Mailcow\Scim\Service\TokenService;
use Mailcow\Scim\Service\UserService;
use Redis;
use Throwable;

/**
 * The SCIM 2.0 HTTP API below /scim/v2 (RFC 7644), called by scim.php: authentication, routing, list responses
 * and errors. Requests and errors are logged to the Redis list SCIM_LOG; failed authentications go to fail2ban.
 */
class ScimController
{
    private const ALLOW = 'GET, POST, PUT, PATCH, DELETE, OPTIONS';

    public function __construct(private TokenService $tokens, private UserService $users, private GroupService $groups,
        public readonly string $base, private ?Redis $redis)
    {
    }

    /**
     * @param string $path below /scim/v2, without leading slash, still percent-encoded
     * @param array $query query parameters
     */
    public function handle(string $method, string $path, array $query, string $body, string $contentType, string $authorization, string $ip): Response
    {
        $request = $method . ' /scim/v2/' . $path;
        try {
            // CORS preflights carry no Authorization
            if ($method === 'OPTIONS') {
                return new Response(204, null, ['Allow: ' . self::ALLOW]);
            }
            try {
                $token = $this->tokens->authenticate($authorization, $ip);
            } catch (ScimError $e) {
                if ($authorization !== '') {
                    $this->redis?->publish('F2B_CHANNEL', 'mailcow UI: Invalid password for SCIM token by ' . $ip);
                }
                throw $e;
            }
            $this->log('info', $request . ' from ' . $ip . ' (token ID ' . $token->id . ')');
            $segments = ($path === '') ? [] : array_map('rawurldecode', explode('/', trim($path, '/')));
            return $this->route($token, $method, $segments, array_change_key_case($query, CASE_LOWER),
                fn(): array => self::body($body, $contentType));
        } catch (ScimError $e) {
            $this->log('err', $request . ' -> ' . $e->status . ($e->scimType ? ' ' . $e->scimType : '') . ': ' . $e->getMessage());
            return self::error($e);
        } catch (Throwable $e) {
            $this->log('err', $request . ' -> 500: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
            return self::error(new ScimError(500, 'Internal server error'));
        }
    }

    /** @param callable(): array $body reads the request body when the route needs one */
    private function route(Token $token, string $method, array $segments, array $query, callable $body): Response
    {
        [$resource, $id] = [$segments[0] ?? '', $segments[1] ?? null];
        if ($resource === '' || count($segments) > 2) {
            throw ScimError::notFound('Not found');
        }
        switch ($resource) {
            case 'ServiceProviderConfig':
            case 'Schemas':
            case 'ResourceTypes':
                self::allow($method, 'GET');
                // RFC 7644 4: a filter SHOULD be answered with 403
                if (($query['filter'] ?? '') !== '') {
                    throw new ScimError(403, 'Filtering is not supported on configuration endpoints');
                }
                return new Response(200, $this->configuration($resource, $id));
            case 'Users':
            case 'Groups':
                $type = substr($resource, 0, -1);
                if ($id === '.search') {
                    self::allow($method, 'POST');
                    return $this->search([$type], $token, $body());
                }
                if ($id === null) {
                    self::allow($method, 'GET, POST');
                    return ($method === 'GET') ? $this->list([$type], $token, $query) : $this->create($type, $token, $body(), $query);
                }
                self::allow($method, 'GET, PUT, PATCH, DELETE');
                return $this->resource($type, $token, $method, $id, $query, $body);
            case '.search':
                if ($id !== null) {
                    throw ScimError::notFound('Not found');
                }
                self::allow($method, 'POST');
                return $this->search(['User', 'Group'], $token, $body());
            case 'Me':
                // RFC 7644 3.11: optional
                throw new ScimError(501, 'The /Me endpoint is not implemented');
            default:
                throw ScimError::notFound("Resource type '$resource' not found");
        }
    }

    private function configuration(string $resource, ?string $id): array
    {
        if ($resource === 'ServiceProviderConfig') {
            return ($id === null) ? Schema::serviceProviderConfig($this->base) : throw ScimError::notFound('Not found');
        }
        $items = ($resource === 'Schemas') ? Schema::schemas($this->base) : Schema::resourceTypes($this->base);
        if ($id === null) {
            return self::listResponse($items, count($items), 1);
        }
        foreach ($items as $item) {
            if (strcasecmp($item['id'], $id) === 0) {
                return $item;
            }
        }
        throw ScimError::notFound("$resource '$id' not found");
    }

    private function create(string $type, Token $token, array $body, array $query): Response
    {
        $resource = $this->service($type)->create($token, $body)->toResource($this->base);
        $this->log('info', "Created $type " . ($resource['userName'] ?? $resource['displayName']) . ' (token ID ' . $token->id . ')');
        return new Response(201, Schema::project($resource, $type, $query['attributes'] ?? null, $query['excludedattributes'] ?? null),
            ['Location: ' . $resource['meta']['location']]);
    }

    private function resource(string $type, Token $token, string $method, string $id, array $query, callable $body): Response
    {
        $service = $this->service($type);
        if ($method === 'DELETE') {
            $name = ($type === 'User') ? $service->get($token, $id)->username : $service->get($token, $id)->name;
            $service->delete($token, $id);
            $this->log('info', "Deleted $type $name: removed from SCIM" . (($type === 'User') ? ', login disabled, mailbox kept' : ', mailbox group kept')
                . ' (token ID ' . $token->id . ')');
            return new Response(204);
        }
        $result = match ($method) {
            'GET' => $service->get($token, $id),
            'PUT' => $service->replace($token, $id, $body()),
            'PATCH' => $service->patch($token, $id, $body()),
        };
        // RFC 7644 3.5.2: a PATCH may answer 204; groups do unless attributes are requested (their member lists can be long)
        if ($method === 'PATCH' && $type === 'Group' && !Schema::projects($query)) {
            return new Response(204);
        }
        return new Response(200, Schema::project($result->toResource($this->base), $type, $query['attributes'] ?? null, $query['excludedattributes'] ?? null));
    }

    /** POST .search (RFC 7644 3.4.3): the query as body */
    private function search(array $types, Token $token, array $body): Response
    {
        Schema::requireSchema($body, Schema::SEARCH);
        // sortBy/sortOrder are ignored, sorting is not supported (RFC 7644 3.4.2.3)
        return $this->list($types, $token, $body);
    }

    /**
     * GET of a collection: filter, pagination (RFC 7644 3.4.2.4) and attribute projection. Several types (root
     * .search): a filter attribute that one type does not know matches none of its resources.
     */
    private function list(array $types, Token $token, array $query): Response
    {
        $filter = $query['filter'] ?? '';
        if (!is_string($filter)) {
            throw new ScimError(400, "'filter' must be a string", 'invalidFilter');
        }
        $start = max(1, (int)(is_numeric($query['startindex'] ?? null) ? $query['startindex'] : 1));
        $count = is_numeric($query['count'] ?? null) ? min(500, max(0, (int)$query['count'])) : 100;
        $matches = [];
        $errors = [];
        foreach ($types as $type) {
            try {
                $parsed = ($filter === '') ? null : Filter::parse($filter, $type);
            } catch (ScimError $e) {
                $errors[] = $e;
                continue;
            }
            foreach ($this->service($type)->list($token) as $item) {
                $resource = $item->toResource($this->base);
                if ($parsed === null || $parsed->matches($resource)) {
                    $matches[] = [$type, $resource];
                }
            }
        }
        if (count($errors) === count($types)) {
            throw $errors[0];
        }
        $page = ($count > 0) ? array_slice($matches, $start - 1, $count) : [];
        $page = array_map(fn(array $match): array => Schema::project($match[1], $match[0], $query['attributes'] ?? null,
            $query['excludedattributes'] ?? null), $page);
        return new Response(200, self::listResponse($page, count($matches), $start));
    }

    private function service(string $type): UserService|GroupService
    {
        return ($type === 'User') ? $this->users : $this->groups;
    }

    private function log(string $priority, string $message): void
    {
        try {
            $this->redis?->lPush('SCIM_LOG', json_encode(['time' => time(), 'priority' => $priority, 'task' => 'SCIM', 'message' => $message]));
        } catch (Throwable) {
            // logging must not break the response
        }
    }

    private static function listResponse(array $resources, int $total, int $start): array
    {
        return ['schemas' => [Schema::LIST], 'totalResults' => $total, 'startIndex' => $start,
            'itemsPerPage' => count($resources), 'Resources' => $resources];
    }

    /** @throws ScimError 405 with Allow header */
    private static function allow(string $method, string $allowed): void
    {
        if (!in_array($method, explode(', ', $allowed), true)) {
            throw new ScimError(405, 'Method not allowed', null, ['Allow: ' . $allowed . ', OPTIONS']);
        }
    }

    /** JSON body (RFC 7644 3.1) with lowercased keys */
    private static function body(string $body, string $contentType): array
    {
        $mime = strtolower(trim(explode(';', $contentType)[0]));
        if ($mime !== '' && !in_array($mime, ['application/scim+json', 'application/json'], true)) {
            throw new ScimError(415, "Unsupported media type '$mime', use application/scim+json");
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new ScimError(400, (trim($body) === '') ? 'Request body is required' : 'Request body is not valid JSON', 'invalidSyntax');
        }
        return Schema::lowerKeys($decoded);
    }

    private static function error(ScimError $e): Response
    {
        $body = ['schemas' => [Schema::ERROR], 'status' => (string)$e->status, 'detail' => $e->getMessage()];
        if ($e->scimType !== null) {
            $body['scimType'] = $e->scimType;
        }
        $headers = $e->headers;
        if ($e->status === 401 && !preg_grep('/^WWW-Authenticate:/i', $headers)) {
            $headers[] = 'WWW-Authenticate: Bearer realm="mailcow SCIM"';
        }
        return new Response($e->status, $body, $headers);
    }
}
