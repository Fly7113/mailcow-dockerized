<?php

declare(strict_types=1);

namespace Mailcow\Scim\Model;

/**
 * A SCIM Group: a mailbox group with a `scim_group_maps` row. Its members are the group members that are
 * SCIM users visible to the token; address, send-as, shares and template are maintained in mailcow.
 */
class Group
{
    public string $scimId = '';
    public int $groupId = 0;
    public string $domain = '';
    public string $name = '';
    public ?string $externalId = null;
    /** @var array<string, string> SCIM id => username */
    public array $members = [];
    public ?string $created = null;
    public ?string $modified = null;

    /** Builds a group from a `mailbox_group` row joined with its `scim_group_maps` columns (scim_id, external_id) */
    public static function fromRow(array $row): self
    {
        $group = new self();
        $group->scimId = (string)$row['scim_id'];
        $group->groupId = (int)$row['id'];
        $group->domain = (string)$row['domain'];
        $group->name = (string)$row['name'];
        $group->externalId = ($row['external_id'] ?? '') !== '' ? (string)$row['external_id'] : null;
        $group->created = isset($row['created']) ? (string)$row['created'] : null;
        $group->modified = isset($row['modified']) ? (string)$row['modified'] : null;
        return $group;
    }

    /** SCIM representation (RFC 7643 4.2) */
    public function toResource(string $base): array
    {
        $resource = ['schemas' => [Schema::GROUP], 'id' => $this->scimId];
        if ($this->externalId !== null) {
            $resource['externalId'] = $this->externalId;
        }
        $resource['displayName'] = $this->name;
        $resource['members'] = [];
        foreach ($this->members as $id => $username) {
            $resource['members'][] = ['value' => (string)$id, '$ref' => $base . '/Users/' . rawurlencode((string)$id),
                'type' => 'User', 'display' => $username];
        }
        $resource['meta'] = array_filter([
            'resourceType' => 'Group',
            'created' => Schema::time($this->created),
            'lastModified' => Schema::time($this->modified),
            'location' => $base . '/Groups/' . rawurlencode($this->scimId),
        ], fn(?string $value): bool => $value !== null);
        return $resource;
    }
}
