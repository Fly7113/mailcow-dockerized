<?php

declare(strict_types=1);

namespace Mailcow\Tests\Scim\Service;

use Mailcow\Core\UserError;
use Mailcow\MailboxGroup\Model\Group as MailboxGroup;
use Mailcow\MailboxGroup\Service\GroupService as MailboxGroupService;
use Mailcow\MailboxGroup\Service\IdpSyncService;
use Mailcow\Scim\Model\Group;
use Mailcow\Scim\Model\Schema;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\Model\User;
use Mailcow\Scim\Repository\GroupRepository;
use Mailcow\Scim\Repository\UserRepository;
use Mailcow\Scim\ScimError;
use Mailcow\Scim\Service\GroupService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class GroupServiceTest extends TestCase
{
    private GroupRepository&MockObject $groups;
    private UserRepository&MockObject $users;
    private MailboxGroupService&MockObject $mailboxGroups;
    private IdpSyncService&MockObject $idp;
    private GroupService $service;
    private Token $token;

    protected function setUp(): void
    {
        $this->groups = $this->createMock(GroupRepository::class);
        $this->users = $this->createMock(UserRepository::class);
        $this->mailboxGroups = $this->createMock(MailboxGroupService::class);
        $this->idp = $this->createMock(IdpSyncService::class);
        $this->service = new GroupService($this->groups, $this->users, $this->mailboxGroups, $this->idp);
        $this->token = Token::fromRow(['id' => 7, 'group_domain' => 'example.org']);
        // SCIM users u-1 .. u-3 = a@, b@, c@example.org
        $this->users->method('find')->willReturnCallback(fn(string $id): ?User => in_array($id, ['u-1', 'u-2', 'u-3'], true)
            ? User::fromRow(['scim_id' => $id, 'username' => ['u-1' => 'a', 'u-2' => 'b', 'u-3' => 'c'][$id] . '@example.org',
                'domain' => 'example.org', 'active' => 1]) : null);
    }

    private static function group(array $members = ['u-1' => 'a@example.org', 'u-2' => 'b@example.org']): Group
    {
        $group = Group::fromRow(['id' => 5, 'scim_id' => 'g-1', 'domain' => 'example.org', 'name' => 'Sales', 'external_id' => 'ext-g']);
        $group->members = $members;
        return $group;
    }

    private static function patch(array ...$operations): array
    {
        return ['schemas' => [Schema::PATCH], 'operations' => $operations];
    }

    private function expectScimError(int $status, ?string $scimType, callable $call): void
    {
        try {
            $call();
            $this->fail("ScimError $status expected");
        } catch (ScimError $e) {
            $this->assertSame([$status, $scimType], [$e->status, $e->scimType], $e->getMessage());
        }
    }

    public function testCreateInTheGroupDomain(): void
    {
        $created = MailboxGroup::fromRow(['id' => 5, 'domain' => 'example.org', 'name' => 'Sales']);
        $this->mailboxGroups->expects($this->once())->method('create')->with(['domain' => 'example.org', 'name' => 'Sales'])->willReturn($created);
        $this->groups->expects($this->once())->method('link')->with($this->anything(), 5, 'ext-g', 7);
        $this->idp->expects($this->once())->method('syncGroupMembers')->with(5, ['a@example.org']);
        $this->groups->method('find')->willReturn(self::group());

        // extra schema URN of Entra ID
        $this->service->create($this->token, ['schemas' => [Schema::GROUP, 'http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group'],
            'displayname' => ' Sales ', 'externalid' => 'ext-g', 'members' => [['value' => 'u-1']]]);
    }

    public function testTheRestrictedDomainIsTheGroupDomain(): void
    {
        $this->token->domainRestriction = 'example.com';
        $this->groups->method('nameTaken')->with('example.com', 'Sales')->willReturn(true);
        $this->expectScimError(409, 'uniqueness', fn() => $this->service->create($this->token, ['schemas' => [Schema::GROUP], 'displayname' => 'Sales']));
    }

    public static function invalidGroups(): array
    {
        return [
            'no group domain' => [['displayname' => 'Sales'], null, 400, 'invalidValue'],
            'no displayName' => [['members' => []], 'example.org', 400, 'invalidValue'],
            'nested group' => [['displayname' => 'Sales', 'members' => [['value' => 'g-2', 'type' => 'Group']]], 'example.org', 400, 'invalidValue'],
            'unknown member' => [['displayname' => 'Sales', 'members' => [['value' => 'u-9']]], 'example.org', 400, 'invalidValue'],
        ];
    }

    #[DataProvider('invalidGroups')]
    public function testInvalidGroupsAreNotCreated(array $body, ?string $groupDomain, int $status, string $scimType): void
    {
        $this->token->groupDomain = $groupDomain;
        $this->mailboxGroups->expects($this->never())->method('create');
        $this->expectScimError($status, $scimType, fn() => $this->service->create($this->token, $body + ['schemas' => [Schema::GROUP]]));
    }

    public function testMailcowRejectionsAreMapped(): void
    {
        $this->mailboxGroups->method('create')->willThrowException(new UserError('object_exists', ['Sales']));
        $this->expectScimError(409, 'uniqueness', fn() => $this->service->create($this->token, ['schemas' => [Schema::GROUP], 'displayname' => 'Sales']));
    }

    /** The PATCH requests of Entra ID, Okta and Authentik */
    public static function memberPatches(): array
    {
        return [
            'add (Entra ID)' => [[['op' => 'Add', 'path' => 'members', 'value' => [['$ref' => null, 'value' => 'u-3']]]],
                ['a@example.org', 'b@example.org', 'c@example.org']],
            'add an existing member is a no-op' => [[['op' => 'add', 'path' => 'members', 'value' => [['value' => 'u-1']]]], null],
            'remove with value list (Entra ID default)' => [[['op' => 'Remove', 'path' => 'members', 'value' => [['value' => 'u-1']]]],
                ['b@example.org']],
            'remove by value filter (RFC, Okta, Authentik)' => [[['op' => 'remove', 'path' => 'members[value eq "u-2"]']], ['a@example.org']],
            'remove a non-member is a no-op' => [[['op' => 'remove', 'path' => 'members[value eq "u-9"]']], null],
            'remove all' => [[['op' => 'remove', 'path' => 'members']], []],
            'replace' => [[['op' => 'replace', 'path' => 'members', 'value' => [['value' => 'u-3']]]], ['c@example.org']],
            'path-less add' => [[['op' => 'add', 'value' => ['members' => [['value' => 'u-3']]]]], ['a@example.org', 'b@example.org', 'c@example.org']],
            'remove and add in one request' => [[
                ['op' => 'remove', 'path' => 'members[value eq "u-1"]'],
                ['op' => 'add', 'path' => 'members', 'value' => [['value' => 'u-3']]],
            ], ['b@example.org', 'c@example.org']],
        ];
    }

    #[DataProvider('memberPatches')]
    public function testPatchMembers(array $operations, ?array $expected): void
    {
        $this->groups->method('find')->willReturn(self::group());
        // an IdP member of another domain, invisible to a restricted token, stays
        $this->groups->method('idpMembers')->willReturn(['a@example.org', 'b@example.org', 'x@example.net']);
        if ($expected === null) {
            $this->idp->expects($this->never())->method('syncGroupMembers');
        } else {
            $this->idp->expects($this->once())->method('syncGroupMembers')->with(5, $this->callback(
                fn(array $usernames): bool => self::sorted($usernames) === self::sorted(array_merge($expected, ['x@example.net']))));
        }
        $this->service->patch($this->token, 'g-1', self::patch(...$operations));
    }

    private static function sorted(array $values): array
    {
        sort($values);
        return $values;
    }

    public function testPatchRename(): void
    {
        $this->groups->method('find')->willReturn(self::group());
        $this->idp->expects($this->once())->method('renameFromIdp')->with(5, 'Marketing');
        $this->idp->expects($this->never())->method('syncGroupMembers');
        // Okta/Authentik: path-less replace repeating id and schemas
        $this->service->patch($this->token, 'g-1', self::patch(['op' => 'replace', 'value' => ['id' => 'g-1', 'schemas' => [Schema::GROUP], 'displayname' => 'Marketing']]));
    }

    public function testPatchIsAtomic(): void
    {
        $this->groups->method('find')->willReturn(self::group());
        $this->idp->expects($this->never())->method($this->anything());
        $this->groups->expects($this->never())->method('setExternalId');
        $this->expectScimError(400, 'invalidValue', fn() => $this->service->patch($this->token, 'g-1', self::patch(
            ['op' => 'replace', 'path' => 'displayName', 'value' => 'Marketing'],
            ['op' => 'add', 'path' => 'members', 'value' => [['value' => 'u-9']]],
        )));
        $this->expectScimError(400, 'invalidValue', fn() => $this->service->patch($this->token, 'g-1',
            self::patch(['op' => 'remove', 'path' => 'displayName'])));
        $this->expectScimError(400, 'mutability', fn() => $this->service->patch($this->token, 'g-1',
            self::patch(['op' => 'replace', 'path' => 'id', 'value' => 'g-2'])));
    }

    public function testDeleteKeepsTheMailboxGroup(): void
    {
        $this->groups->method('find')->willReturn(self::group());
        $this->idp->expects($this->once())->method('syncGroupMembers')->with(5, []);
        $this->groups->expects($this->once())->method('unlink')->with(5);
        $this->mailboxGroups->expects($this->never())->method('delete');
        $this->service->delete($this->token, 'g-1');
    }

    public function testRemoveMemberFromAllScimGroups(): void
    {
        $this->groups->method('idpGroupsOf')->with('a@example.org')->willReturn([5, 6]);
        $this->groups->method('idpMembers')->willReturnMap([[5, ['a@example.org', 'b@example.org']], [6, ['a@example.org']]]);
        $calls = [];
        $this->idp->method('syncGroupMembers')->willReturnCallback(function (int $id, array $usernames) use (&$calls): array {
            $calls[$id] = $usernames;
            return [];
        });
        $this->service->removeMember('a@example.org');
        $this->assertSame([5 => ['b@example.org'], 6 => []], $calls);
    }
}
