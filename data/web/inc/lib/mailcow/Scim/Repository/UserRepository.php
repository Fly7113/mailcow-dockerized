<?php

declare(strict_types=1);

namespace Mailcow\Scim\Repository;

use Mailcow\Core\Repository;
use Mailcow\Scim\Model\User;
use PDO;

/**
 * SQL for the SCIM users: `scim_maps` joined with their mailboxes (authsource 'scim').
 */
class UserRepository extends Repository
{
    private const SELECT = "SELECT m.`username`, m.`domain`, m.`name`, m.`active`, m.`created`, m.`modified`,
        s.`scim_id`, s.`external_id`, s.`template`, s.`disabled`
      FROM `scim_maps` s JOIN `mailbox` m ON m.`username` = s.`username` AND m.`authsource` = 'scim'";

    public function find(string $scimId, ?string $domain): ?User
    {
        $row = $this->query(self::SELECT . " WHERE s.`scim_id` = :id AND (:domain IS NULL OR m.`domain` = :domain2)",
            ['id' => $scimId, 'domain' => $domain, 'domain2' => $domain])->fetch(PDO::FETCH_ASSOC);
        return $row ? User::fromRow($row) : null;
    }

    /** @return User[] ordered by username, of one domain or all */
    public function all(?string $domain): array
    {
        return array_map([User::class, 'fromRow'], $this->query(self::SELECT . " WHERE (:domain IS NULL OR m.`domain` = :domain2)
            ORDER BY m.`username`", ['domain' => $domain, 'domain2' => $domain])->fetchAll(PDO::FETCH_ASSOC));
    }

    /** @return ?array{authsource: string, linked: bool} the mailbox of an address, null when there is none */
    public function mailbox(string $username): ?array
    {
        $row = $this->query("SELECT m.`authsource`, s.`id` IS NOT NULL AS `linked` FROM `mailbox` m
            LEFT JOIN `scim_maps` s ON s.`username` = m.`username` WHERE m.`username` = :username", ['username' => $username])
            ->fetch(PDO::FETCH_ASSOC);
        return $row ? ['authsource' => (string)$row['authsource'], 'linked' => (bool)$row['linked']] : null;
    }

    public function externalIdTaken(string $externalId, ?string $exceptUsername = null): bool
    {
        return (bool)$this->query("SELECT 1 FROM `scim_maps` WHERE `external_id` = :id AND `username` != :username",
            ['id' => $externalId, 'username' => $exceptUsername ?? ''])->fetchColumn();
    }

    public function link(string $scimId, string $username, ?string $externalId, ?int $tokenId, ?string $template, int $disabled): void
    {
        $this->insertRow('scim_maps', ['scim_id' => $scimId, 'username' => $username, 'external_id' => $externalId,
            'token_id' => $tokenId, 'template' => $template, 'disabled' => $disabled]);
    }

    /** Sets columns of the user's `scim_maps` row (external_id, template, disabled) */
    public function update(string $username, array $values): void
    {
        if ($values === []) {
            return;
        }
        $set = implode(', ', array_map(fn(string $column): string => "`$column` = :$column", array_keys($values)));
        $this->query("UPDATE `scim_maps` SET $set WHERE `username` = :username", $values + ['username' => $username]);
    }

    public function unlink(string $username): void
    {
        $this->query("DELETE FROM `scim_maps` WHERE `username` = :username", ['username' => $username]);
    }
}
