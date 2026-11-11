<?php

declare(strict_types=1);

namespace Mailcow\Tests\Scim\Service;

use Mailcow\Scim\Legacy\LegacyMailboxes;
use Mailcow\Scim\Model\Schema;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\Model\User;
use Mailcow\Scim\Repository\UserRepository;
use Mailcow\Scim\ScimError;
use Mailcow\Scim\Service\GroupService;
use Mailcow\Scim\Service\UserService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class UserServiceTest extends TestCase
{
    private UserRepository&MockObject $users;
    private LegacyMailboxes&MockObject $legacy;
    private GroupService&MockObject $groups;
    private UserService $service;
    private Token $token;

    protected function setUp(): void
    {
        $this->users = $this->createMock(UserRepository::class);
        $this->legacy = $this->createMock(LegacyMailboxes::class);
        $this->groups = $this->createMock(GroupService::class);
        $this->service = new UserService($this->users, $this->legacy, $this->groups);
        $this->token = Token::fromRow(['id' => 7, 'default_template' => 'Default', 'mappers' => '["staff"]', 'templates' => '["Staff"]']);
    }

    private static function user(array $row = []): User
    {
        return User::fromRow($row + ['scim_id' => 'u-1', 'username' => 'jane@example.org', 'domain' => 'example.org',
            'name' => 'Jane Doe', 'active' => 1, 'external_id' => 'ext-1', 'template' => 'Staff', 'disabled' => 0]);
    }

    private static function body(array $attributes = []): array
    {
        return $attributes + ['schemas' => [Schema::USER], 'username' => 'Jane@Example.org', 'name' => ['givenname' => 'Jane', 'familyname' => 'Doe']];
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

    public function testCreateProvisionsAMailboxWithTheMappedTemplate(): void
    {
        $this->users->method('mailbox')->with('jane@example.org')->willReturn(null);
        $this->legacy->expects($this->once())->method('create')->with('jane', 'example.org', 'Jane Doe', 1, 'Staff')->willReturn(null);
        $this->users->expects($this->once())->method('link')->with($this->anything(), 'jane@example.org', 'ext-1', 7, 'Staff', 0);
        $this->users->method('find')->willReturn(self::user());

        $body = self::body(['externalid' => 'ext-1', strtolower(Schema::EXT) => ['template' => 'staff']]);
        $this->assertSame('u-1', $this->service->create($this->token, $body)->scimId);
    }

    public function testCreateInactiveDisallowsTheLogin(): void
    {
        $this->users->method('mailbox')->willReturn(null);
        $this->legacy->expects($this->once())->method('create')->with('jane', 'example.org', 'Jane Doe', 2, 'Default')->willReturn(null);
        $this->users->expects($this->once())->method('link')->with($this->anything(), 'jane@example.org', null, 7, 'Default', 1);
        $this->users->method('find')->willReturn(self::user());

        $this->service->create($this->token, self::body(['active' => 'False']));
    }

    public function testCreateAdoptsAScimMailboxWithoutLink(): void
    {
        $this->users->method('mailbox')->willReturn(['authsource' => 'scim', 'linked' => false]);
        $this->legacy->expects($this->never())->method('create');
        $this->legacy->expects($this->once())->method('applyTemplate')->with('jane@example.org', 'Jane Doe', 'Default')->willReturn(null);
        $this->legacy->expects($this->once())->method('edit')->with('jane@example.org', ['name' => 'Jane Doe', 'active' => 1])->willReturn(null);
        $this->users->expects($this->once())->method('link');
        $this->users->method('find')->willReturn(self::user());

        $this->service->create($this->token, self::body());
    }

    public static function conflicts(): array
    {
        return [
            'linked SCIM user' => [['authsource' => 'scim', 'linked' => true], false],
            'mailbox of another authsource' => [['authsource' => 'mailcow', 'linked' => false], false],
            'externalId of another user' => [null, true],
        ];
    }

    #[DataProvider('conflicts')]
    public function testCreateConflictsAre409(?array $mailbox, bool $externalIdTaken): void
    {
        $this->users->method('mailbox')->willReturn($mailbox);
        $this->users->method('externalIdTaken')->willReturn($externalIdTaken);
        $this->legacy->expects($this->never())->method($this->anything());
        $this->users->expects($this->never())->method('link');

        $this->expectScimError(409, 'uniqueness', fn() => $this->service->create($this->token, self::body(['externalid' => 'ext-1'])));
    }

    public function testCreateRespectsTheDomainRestriction(): void
    {
        $this->token->domainRestriction = 'example.com';
        $this->users->expects($this->never())->method('mailbox');
        $this->expectScimError(403, null, fn() => $this->service->create($this->token, self::body()));
        $this->expectScimError(400, 'invalidValue', fn() => $this->service->create($this->token, self::body(['username' => 'no-address'])));
    }

    public function testMailcowErrorsAre400(): void
    {
        $this->users->method('mailbox')->willReturn(null);
        $this->legacy->method('create')->willReturn('mailbox_quota_exceeded');
        $this->users->expects($this->never())->method('link');
        $this->expectScimError(400, 'invalidValue', fn() => $this->service->create($this->token, self::body()));
    }

    /** active: SCIM disallows logins of active mailboxes and only allows again what it disallowed; admin states win */
    public static function activeChanges(): array
    {
        return [
            'deactivate an active mailbox' => [1, 0, false, ['active' => 2], ['disabled' => 1]],
            'deactivate a mailbox an admin disabled' => [0, 0, false, null, []],
            'deactivate twice' => [2, 1, false, null, []],
            'deactivate a mailbox an admin enabled again' => [1, 1, false, null, []],
            'activate what SCIM disabled' => [2, 1, true, ['active' => 1], ['disabled' => 0]],
            'activate a mailbox an admin enabled meanwhile' => [1, 1, true, null, ['disabled' => 0]],
            'activate a mailbox an admin disabled' => [2, 0, true, null, []],
        ];
    }

    #[DataProvider('activeChanges')]
    public function testActive(int $active, int $disabled, bool $wanted, ?array $edit, array $map): void
    {
        $this->users->method('find')->willReturn(self::user(['active' => $active, 'disabled' => $disabled]));
        if ($edit === null) {
            $this->legacy->expects($this->never())->method('edit');
        } else {
            $this->legacy->expects($this->once())->method('edit')->with('jane@example.org', $edit)->willReturn(null);
        }
        $this->users->expects($this->once())->method('update')->with('jane@example.org', $map);

        $this->service->patch($this->token, 'u-1', self::patch(['op' => 'replace', 'path' => 'active', 'value' => $wanted]));
    }

    public function testPatchIsAtomic(): void
    {
        $this->users->method('find')->willReturn(self::user());
        $this->users->method('externalIdTaken')->willReturn(true);
        $this->legacy->expects($this->never())->method($this->anything());
        $this->users->expects($this->never())->method('update');

        $this->expectScimError(409, 'uniqueness', fn() => $this->service->patch($this->token, 'u-1', self::patch(
            ['op' => 'replace', 'path' => 'displayName', 'value' => 'Jane Roe'],
            ['op' => 'replace', 'path' => 'externalId', 'value' => 'ext-2'],
        )));
    }

    public function testPatchNames(): void
    {
        $this->users->method('find')->willReturn(self::user());
        $this->legacy->expects($this->once())->method('edit')->with('jane@example.org', ['name' => 'Janet Roe'])->willReturn(null);

        // Entra ID: path-less operation with paths as keys; any order of name operations converges
        $this->service->patch($this->token, 'u-1', self::patch(
            ['op' => 'Replace', 'value' => ['name.familyname' => 'Roe', 'title' => 'ignored']],
            ['op' => 'replace', 'path' => 'name.givenName', 'value' => 'Janet'],
            ['op' => 'add', 'path' => 'emails[type eq "work"].value', 'value' => 'jane@example.org'],
        ));
    }

    public function testImmutableAttributes(): void
    {
        $this->users->method('find')->willReturn(self::user());
        $this->legacy->expects($this->never())->method($this->anything());

        $this->expectScimError(400, 'mutability', fn() => $this->service->patch($this->token, 'u-1',
            self::patch(['op' => 'replace', 'path' => 'userName', 'value' => 'john@example.org'])));
        $this->expectScimError(400, 'mutability', fn() => $this->service->patch($this->token, 'u-1',
            self::patch(['op' => 'replace', 'path' => 'emails[type eq "work"].value', 'value' => 'john@example.org'])));
        $this->expectScimError(400, 'mutability', fn() => $this->service->patch($this->token, 'u-1',
            self::patch(['op' => 'replace', 'path' => Schema::EXT . ':template', 'value' => 'Default'])));
        // the applied template sent back unchanged (GET-modify-PUT) is no change
        $this->users->expects($this->once())->method('update')->with('jane@example.org', []);
        $this->service->patch($this->token, 'u-1', self::patch(['op' => 'replace', 'path' => Schema::EXT . ':template', 'value' => 'Staff']));
    }

    public function testPutReplacesAndClearsOmittedAttributes(): void
    {
        $this->users->method('find')->willReturn(self::user(['active' => 2, 'disabled' => 1]));
        $this->legacy->expects($this->once())->method('edit')->with('jane@example.org', ['active' => 1])->willReturn(null);
        // externalId omitted = cleared, active omitted = true
        $this->users->expects($this->once())->method('update')->with('jane@example.org', ['external_id' => null, 'disabled' => 0]);

        $this->service->replace($this->token, 'u-1', self::body());
    }

    public function testDeleteDisallowsTheLoginAndUnlinks(): void
    {
        $this->users->method('find')->willReturn(self::user());
        $this->groups->expects($this->once())->method('removeMember')->with('jane@example.org');
        $this->legacy->expects($this->once())->method('edit')->with('jane@example.org', ['active' => 2])->willReturn(null);
        $this->users->expects($this->once())->method('unlink')->with('jane@example.org');

        $this->service->delete($this->token, 'u-1');
    }

    public function testUnknownUsersAre404(): void
    {
        $this->users->method('find')->willReturn(null);
        $this->expectScimError(404, null, fn() => $this->service->get($this->token, 'nope'));
        $this->expectScimError(404, null, fn() => $this->service->delete($this->token, 'nope'));
    }
}
