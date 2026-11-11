<?php

declare(strict_types=1);

namespace Mailcow\Tests\Scim\Controller;

use Mailcow\Scim\Controller\ScimController;
use Mailcow\Scim\Model\Group;
use Mailcow\Scim\Model\Schema;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\Model\User;
use Mailcow\Scim\ScimError;
use Mailcow\Scim\Service\GroupService;
use Mailcow\Scim\Service\TokenService;
use Mailcow\Scim\Service\UserService;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ScimControllerTest extends TestCase
{
    private const BASE = 'https://mail.example.org/scim/v2';

    private TokenService&MockObject $tokens;
    private UserService&MockObject $users;
    private GroupService&MockObject $groups;
    private ScimController $controller;

    protected function setUp(): void
    {
        $this->tokens = $this->createMock(TokenService::class);
        $this->tokens->method('authenticate')->willReturnCallback(fn(string $header): Token => ($header === 'Bearer t')
            ? Token::fromRow(['id' => 1]) : throw new ScimError(401, 'Invalid or inactive token'));
        $this->users = $this->createMock(UserService::class);
        $this->groups = $this->createMock(GroupService::class);
        $this->controller = new ScimController($this->tokens, $this->users, $this->groups, self::BASE, null);
    }

    private function call(string $method, string $path, array $query = [], string $body = '', string $auth = 'Bearer t'): array
    {
        $response = $this->controller->handle($method, $path, $query, $body, 'application/scim+json', $auth, '192.0.2.1');
        return [$response->status, $response->body, $response->headers];
    }

    private static function user(string $id, string $username): User
    {
        return User::fromRow(['scim_id' => $id, 'username' => $username, 'domain' => 'example.org', 'name' => 'X', 'active' => 1]);
    }

    public function testAuthentication(): void
    {
        [$status, $body, $headers] = $this->call('GET', 'Users', [], '', 'Bearer wrong');
        $this->assertSame([401, '401', Schema::ERROR], [$status, $body['status'], $body['schemas'][0]]);
        $this->assertSame(['WWW-Authenticate: Bearer realm="mailcow SCIM"'], $headers);
        // CORS preflight without credentials
        $this->assertSame(204, $this->call('OPTIONS', 'Users', [], '', '')[0]);
    }

    public function testListFilterAndPagination(): void
    {
        $this->users->method('list')->willReturn([self::user('u-1', 'a@example.org'), self::user('u-2', 'b@example.org'), self::user('u-3', 'c@example.org')]);

        [$status, $body] = $this->call('GET', 'Users', ['startIndex' => '2', 'count' => '1', 'excludedAttributes' => 'emails']);
        $this->assertSame([200, 3, 2, 1], [$status, $body['totalResults'], $body['startIndex'], $body['itemsPerPage']]);
        $this->assertSame('b@example.org', $body['Resources'][0]['userName']);
        $this->assertArrayNotHasKey('emails', $body['Resources'][0]);

        $body = $this->call('GET', 'Users', ['filter' => 'userName eq "C@example.org"'])[1];
        $this->assertSame(['u-3'], array_column($body['Resources'], 'id'));

        $this->assertSame(['invalidFilter'], [$this->call('GET', 'Users', ['filter' => 'nope eq 1'])[1]['scimType']]);
    }

    public function testRootSearchCoversUsersAndGroups(): void
    {
        $this->users->method('list')->willReturn([self::user('u-1', 'sales@example.org')]);
        $group = Group::fromRow(['id' => 5, 'scim_id' => 'g-1', 'domain' => 'example.org', 'name' => 'Sales']);
        $this->groups->method('list')->willReturn([$group]);

        // displayName is known to both types, userName only to users
        $body = $this->call('POST', '.search', [], json_encode(['schemas' => [Schema::SEARCH], 'filter' => 'displayName eq "Sales"']))[1];
        $this->assertSame(['g-1'], array_column($body['Resources'], 'id'));
        $body = $this->call('POST', '.search', [], json_encode(['schemas' => [Schema::SEARCH], 'filter' => 'userName sw "sales"']))[1];
        $this->assertSame(['u-1'], array_column($body['Resources'], 'id'));
    }

    public function testCreateAnswers201WithLocation(): void
    {
        $this->users->method('create')->willReturn(self::user('u-1', 'a@example.org'));
        [$status, $body, $headers] = $this->call('POST', 'Users', [], json_encode(['schemas' => [Schema::USER], 'userName' => 'a@example.org']));
        $this->assertSame(201, $status);
        $this->assertSame(['Location: ' . self::BASE . '/Users/u-1'], $headers);
        $this->assertSame('User', $body['meta']['resourceType']);
    }

    public function testGroupPatchAnswers204UnlessAttributesAreRequested(): void
    {
        $this->groups->method('patch')->willReturn(Group::fromRow(['id' => 5, 'scim_id' => 'g-1', 'domain' => 'example.org', 'name' => 'Sales']));
        $patch = json_encode(['schemas' => [Schema::PATCH], 'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Sales']]]);
        $this->assertSame(204, $this->call('PATCH', 'Groups/g-1', [], $patch)[0]);
        [$status, $body] = $this->call('PATCH', 'Groups/g-1', ['attributes' => 'displayName'], $patch);
        $this->assertSame([200, 'Sales'], [$status, $body['displayName']]);
    }

    public function testDeleteAnswers204(): void
    {
        $this->groups->expects($this->once())->method('delete')->with($this->anything(), 'g-1');
        $this->assertSame([204, null], array_slice($this->call('DELETE', 'Groups/g-1'), 0, 2));
    }

    public function testProtocolErrors(): void
    {
        [$status, , $headers] = $this->call('DELETE', 'Users');
        $this->assertSame([405, ['Allow: GET, POST, OPTIONS']], [$status, $headers]);
        $this->assertSame(415, $this->controller->handle('POST', 'Users', [], '{}', 'text/plain', 'Bearer t', '192.0.2.1')->status);
        $this->assertSame([400, 'invalidSyntax'], [$this->call('POST', 'Users', [], '{nope')[0], $this->call('POST', 'Users', [], '{nope')[1]['scimType']]);
        $this->assertSame(403, $this->call('GET', 'Schemas', ['filter' => 'id pr'])[0]);
        $this->assertSame(404, $this->call('GET', 'Nope')[0]);
        $this->assertSame(501, $this->call('GET', 'Me')[0]);
        $this->assertSame(Schema::GROUP, $this->call('GET', 'Schemas/' . Schema::GROUP)[1]['id']);
        $this->assertSame(['User', 'Group'], array_column($this->call('GET', 'ResourceTypes')[1]['Resources'], 'id'));
        $this->users->method('get')->willThrowException(new \RuntimeException('boom'));
        $this->assertSame([500, 'Internal server error'], [$this->call('GET', 'Users/u-1')[0], $this->call('GET', 'Users/u-1')[1]['detail']]);
    }
}
