<?php

declare(strict_types=1);

namespace Mailcow\Scim\Repository;

use Mailcow\Core\Repository;
use Mailcow\MailboxGroup\Model\Group as MailboxGroup;
use Mailcow\Scim\Model\Group;
use PDO;

/**
 * SQL for the SCIM groups: `scim_group_maps` joined with their mailbox groups. Writes to the mailbox group
 * tables go through the MailboxGroup module.
 */
class GroupRepository extends Repository
{
    private const SELECT = "SELECT g.`id`, g.`domain`, g.`name`, g.`created`, g.`modified`, sg.`scim_id`, sg.`external_id`
      FROM `scim_group_maps` sg JOIN `mailbox_group` g ON g.`id` = sg.`group_id`";

    /** $domain: only a group of this domain, with members of this domain */
    public function find(string $scimId, ?string $domain): ?Group
    {
        $row = $this->query(self::SELECT . " WHERE sg.`scim_id` = :id AND (:domain IS NULL OR g.`domain` = :domain2)",
            ['id' => $scimId, 'domain' => $domain, 'domain2' => $domain])->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->withMembers([Group::fromRow($row)], $domain)[0] : null;
    }

    /** @return Group[] ordered by name, of one domain or all */
    public function all(?string $domain): array
    {
        $rows = $this->query(self::SELECT . " WHERE (:domain IS NULL OR g.`domain` = :domain2) ORDER BY g.`name`, g.`id`",
            ['domain' => $domain, 'domain2' => $domain])->fetchAll(PDO::FETCH_ASSOC);
        return $this->withMembers(array_map([Group::class, 'fromRow'], $rows), $domain);
    }

    public function nameTaken(string $domain, string $name, int $exceptGroupId = 0): bool
    {
        return (bool)$this->query("SELECT 1 FROM `mailbox_group` WHERE `domain` = :domain AND `name` = :name AND `id` != :id",
            ['domain' => $domain, 'name' => $name, 'id' => $exceptGroupId])->fetchColumn();
    }

    public function externalIdTaken(string $externalId, int $exceptGroupId = 0): bool
    {
        return (bool)$this->query("SELECT 1 FROM `scim_group_maps` WHERE `external_id` = :eid AND `group_id` != :id",
            ['eid' => $externalId, 'id' => $exceptGroupId])->fetchColumn();
    }

    public function link(string $scimId, int $groupId, ?string $externalId, ?int $tokenId): void
    {
        $this->insertRow('scim_group_maps', ['scim_id' => $scimId, 'group_id' => $groupId, 'external_id' => $externalId,
            'token_id' => $tokenId]);
    }

    public function setExternalId(int $groupId, ?string $externalId): void
    {
        $this->query("UPDATE `scim_group_maps` SET `external_id` = :eid WHERE `group_id` = :id", ['eid' => $externalId, 'id' => $groupId]);
    }

    public function unlink(int $groupId): void
    {
        $this->query("DELETE FROM `scim_group_maps` WHERE `group_id` = :id", ['id' => $groupId]);
    }

    /** @return int[] SCIM groups the mailbox is an IdP member of */
    public function idpGroupsOf(string $username): array
    {
        return array_map('intval', $this->query("SELECT gm.`group_id` FROM `mailbox_group_member` gm
            JOIN `scim_group_maps` sg ON sg.`group_id` = gm.`group_id` WHERE gm.`username` = :username AND gm.`source` = :source",
            ['username' => $username, 'source' => MailboxGroup::SOURCE_IDP])->fetchAll(PDO::FETCH_COLUMN));
    }

    /** @return string[] IdP members of a group */
    public function idpMembers(int $groupId): array
    {
        return $this->query("SELECT `username` FROM `mailbox_group_member` WHERE `group_id` = :id AND `source` = :source",
            ['id' => $groupId, 'source' => MailboxGroup::SOURCE_IDP])->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * Loads the members that are SCIM users (of $domain, when set) into the groups.
     *
     * @param Group[] $groups
     * @return Group[]
     */
    private function withMembers(array $groups, ?string $domain): array
    {
        if ($groups === []) {
            return [];
        }
        $byId = [];
        $params = ['domain' => $domain, 'domain2' => $domain];
        foreach ($groups as $i => $group) {
            $byId[$group->groupId] = $group;
            $params['g' . $i] = $group->groupId;
        }
        $in = implode(', ', array_map(fn(string $key): string => ':' . $key, array_slice(array_keys($params), 2)));
        $rows = $this->query("SELECT gm.`group_id`, s.`scim_id`, gm.`username` FROM `mailbox_group_member` gm
            JOIN `scim_maps` s ON s.`username` = gm.`username`
            JOIN `mailbox` m ON m.`username` = gm.`username` AND m.`authsource` = 'scim'
          WHERE gm.`group_id` IN ($in) AND (:domain IS NULL OR m.`domain` = :domain2) ORDER BY gm.`username`", $params)
            ->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            $byId[(int)$row['group_id']]->members[(string)$row['scim_id']] = (string)$row['username'];
        }
        return $groups;
    }
}
