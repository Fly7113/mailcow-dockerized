<?php

declare(strict_types=1);

namespace Mailcow\Scim\Service;

use Mailcow\Core\UserError;
use Mailcow\MailboxGroup\Service\GroupService as MailboxGroupService;
use Mailcow\MailboxGroup\Service\IdpSyncService;
use Mailcow\Scim\Model\Group;
use Mailcow\Scim\Model\PatchOp;
use Mailcow\Scim\Model\Schema;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\Repository\GroupRepository;
use Mailcow\Scim\Repository\UserRepository;
use Mailcow\Scim\ScimError;

/**
 * SCIM Groups (RFC 7643 4.2) on mailbox groups, like the Keycloak/LDAP group sync:
 *
 * - A group is created in the token's group domain; name and members follow the IdP. Members are SCIM users,
 *   stored as IdP members (read-only in mailcow); manual members stay. Address, send-as, shares and template
 *   are maintained in mailcow.
 * - DELETE removes the IdP members and the group from SCIM (404 afterwards, RFC 7644 3.6); the mailbox group and
 *   its manual members stay, like a group that disappears from the IdP.
 * - Groups cannot be nested, and an existing mailbox group with the same name is not taken over (409).
 */
class GroupService
{
    public function __construct(private GroupRepository $groups, private UserRepository $users,
        private MailboxGroupService $mailboxGroups, private IdpSyncService $idp)
    {
    }

    /** @return Group[] */
    public function list(Token $token): array
    {
        return $this->groups->all($token->domainRestriction);
    }

    /** @throws ScimError 404, also for groups outside the token's domain */
    public function get(Token $token, string $id): Group
    {
        return $this->groups->find($id, $token->domainRestriction) ?? throw ScimError::notFound('Group not found');
    }

    /** @throws ScimError */
    public function create(Token $token, array $body): Group
    {
        Schema::requireSchema($body, Schema::GROUP);
        $domain = $token->groupDomain() ?? throw ScimError::invalidValue('This SCIM token has no group domain: set one in mailcow to provision groups');
        $name = self::displayName($body['displayname'] ?? null);
        $externalId = self::externalId($body['externalid'] ?? null);
        $members = $this->members($token, $body['members'] ?? null);
        $this->checkUnique($domain, $name, $externalId, 0);
        try {
            $groupId = (int)$this->mailboxGroups->create(['domain' => $domain, 'name' => $name])->id;
        } catch (UserError $e) {
            throw self::rejected($e);
        }
        $id = Schema::uuid();
        $this->groups->link($id, $groupId, $externalId, $token->id);
        if ($members !== []) {
            $this->idp->syncGroupMembers($groupId, array_values($members));
        }
        return $this->get($token, $id);
    }

    /** PUT: replaces name, externalId and members */
    public function replace(Token $token, string $id, array $body): Group
    {
        $group = $this->get($token, $id);
        Schema::requireSchema($body, Schema::GROUP);
        return $this->save($token, $group, self::displayName($body['displayname'] ?? null),
            self::externalId($body['externalid'] ?? null), $this->members($token, $body['members'] ?? null));
    }

    /**
     * PATCH: all operations are applied to a copy and validated before anything is written. Besides RFC 7644,
     * `remove` of `members` with a value list removes only those members (default format of Entra ID).
     */
    public function patch(Token $token, string $id, array $body): Group
    {
        $group = $this->get($token, $id);
        $state = ['id' => $group->scimId, 'name' => $group->name, 'externalId' => $group->externalId, 'members' => $group->members];
        foreach (PatchOp::parse($body, 'Group') as $op) {
            if ($op->path === null) {
                $this->patchObject($token, $state, $op->op, $op->value);
            } else {
                $this->apply($token, $state, $op->op, $op->path, $op->value, $op->hasValue);
            }
        }
        return $this->save($token, $group, $state['name'], $state['externalId'], $state['members']);
    }

    /** DELETE: see the class description */
    public function delete(Token $token, string $id): void
    {
        $group = $this->get($token, $id);
        $this->idp->syncGroupMembers($group->groupId, []);
        $this->groups->unlink($group->groupId);
    }

    /** Removes a mailbox from all SCIM groups (user deleted through SCIM) */
    public function removeMember(string $username): void
    {
        foreach ($this->groups->idpGroupsOf($username) as $groupId) {
            $this->idp->syncGroupMembers($groupId, array_values(array_diff($this->groups->idpMembers($groupId), [$username])));
        }
    }

    /** Path-less operation: an object of attributes, also nested in the core schema URN key */
    private function patchObject(Token $token, array &$state, string $op, array $value): void
    {
        foreach ($value as $key => $v) {
            if ($key === strtolower(Schema::GROUP) && is_array($v)) {
                $this->patchObject($token, $state, $op, $v);
                continue;
            }
            $attr = Schema::attribute('Group', (string)$key) ?? throw new ScimError(400, "Unknown attribute '$key'", 'invalidPath');
            // Okta and Authentik repeat the id in path-less replaces
            if ($attr['parts'] === ['id'] && $v === $state['id']) {
                continue;
            }
            $this->apply($token, $state, $op, ['attr' => $attr, 'filter' => null, 'sub' => null], $v, true);
        }
    }

    /** One operation on a parsed path */
    private function apply(Token $token, array &$state, string $op, array $path, mixed $value, bool $hasValue): void
    {
        $remove = ($op === 'remove');
        switch ($path['attr']['parts'][0]) {
            case 'displayname':
                if ($remove) {
                    throw ScimError::invalidValue("'displayName' is required");
                }
                $state['name'] = self::displayName($value);
                return;
            case 'externalid':
                $state['externalId'] = $remove ? null : self::externalId($value);
                return;
            case 'members':
                if (count($path['attr']['parts']) > 1 || $path['sub'] !== null) {
                    throw ScimError::mutability('Sub-attributes of members are immutable');
                }
                $filter = $path['filter'];
                if ($filter !== null) {
                    // drop the members the value filter matches; replace adds the value then
                    foreach ($state['members'] as $id => $username) {
                        if ($filter->matches(['value' => (string)$id, 'display' => $username, 'type' => 'User'])) {
                            unset($state['members'][$id]);
                        }
                    }
                    if ($op === 'remove') {
                        return;
                    }
                } elseif ($op === 'replace' || ($remove && !$hasValue)) {
                    $state['members'] = [];
                } elseif ($remove) {
                    $state['members'] = array_diff_key($state['members'], array_flip(self::memberIds($value)));
                    return;
                }
                if (!$remove) {
                    $state['members'] = $this->members($token, $value) + $state['members'];
                }
                return;
            case 'id':
                throw ScimError::mutability("'id' is read-only");
            default:
                // schemas, meta: server-controlled, ignored
                return;
        }
    }

    /**
     * Writes name, externalId and members after the checks.
     *
     * @param array<string, string> $members SCIM id => username of the members visible to the token
     */
    private function save(Token $token, Group $group, string $name, ?string $externalId, array $members): Group
    {
        $this->checkUnique($group->domain, ($name !== $group->name) ? $name : null, ($externalId !== $group->externalId) ? $externalId : null, $group->groupId);
        if ($name !== $group->name) {
            try {
                $this->idp->renameFromIdp($group->groupId, $name);
            } catch (UserError $e) {
                throw self::rejected($e);
            }
        }
        if ($externalId !== $group->externalId) {
            $this->groups->setExternalId($group->groupId, $externalId);
        }
        ksort($members);
        $current = $group->members;
        ksort($current);
        if ($members !== $current) {
            // IdP members the token cannot see (other domains) stay
            $hidden = array_diff($this->groups->idpMembers($group->groupId), $group->members);
            $this->idp->syncGroupMembers($group->groupId, array_values(array_unique(array_merge($hidden, array_values($members)))));
        }
        return $this->get($token, $group->scimId);
    }

    /** @throws ScimError uniqueness ($name / $externalId null: not checked) */
    private function checkUnique(string $domain, ?string $name, ?string $externalId, int $groupId): void
    {
        if ($name !== null && $this->groups->nameTaken($domain, $name, $groupId)) {
            throw ScimError::uniqueness("A group '$name' already exists in $domain");
        }
        if ($externalId !== null && $this->groups->externalIdTaken($externalId, $groupId)) {
            throw ScimError::uniqueness("externalId '$externalId' belongs to another group");
        }
    }

    /**
     * Members of a request: users of this provider, visible to the token.
     *
     * @return array<string, string> SCIM id => username
     * @throws ScimError invalidValue
     */
    private function members(Token $token, mixed $items): array
    {
        $members = [];
        foreach (self::memberItems($items) as $item) {
            if (isset($item['type']) && (!is_string($item['type']) || strcasecmp($item['type'], 'User') !== 0)) {
                throw ScimError::invalidValue('Groups cannot be nested, members must be users');
            }
            $id = $item['value'] ?? null;
            $user = is_string($id) ? $this->users->find($id, $token->domainRestriction) : null;
            if ($user === null) {
                throw ScimError::invalidValue("Member '" . (is_scalar($id) ? $id : '') . "' is not a user of this provider");
            }
            $members[$user->scimId] = $user->username;
        }
        return $members;
    }

    /** @return string[] values of member items (for removal; unknown ids are no error) */
    private static function memberIds(mixed $items): array
    {
        return array_map(fn(array $item): string => (string)($item['value'] ?? ''), self::memberItems($items));
    }

    /** @return array[] member objects of a value: a list, a single object or null */
    private static function memberItems(mixed $items): array
    {
        if ($items === null) {
            return [];
        }
        $items = (is_array($items) && !array_is_list($items)) ? [$items] : $items;
        if (!is_array($items) || array_filter($items, fn(mixed $item): bool => !is_array($item) || !is_scalar($item['value'] ?? null))) {
            throw ScimError::invalidValue("'members' must be a list of objects with a value");
        }
        return $items;
    }

    private static function displayName(mixed $value): string
    {
        $name = is_string($value) ? trim($value) : '';
        if ($name === '' || mb_strlen($name) > 100) {
            throw ScimError::invalidValue("'displayName' is required, at most 100 characters");
        }
        return $name;
    }

    private static function externalId(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (!is_scalar($value)) {
            throw ScimError::invalidValue("'externalId' must be a string");
        }
        return trim((string)$value);
    }

    /** A rejected mailbox group change as SCIM error */
    private static function rejected(UserError $e): ScimError
    {
        return ($e->key === 'object_exists') ? ScimError::uniqueness('A group with this name already exists')
            : ScimError::invalidValue('mailcow rejected the group: ' . $e->key);
    }
}
