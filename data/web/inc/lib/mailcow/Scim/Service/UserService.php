<?php

declare(strict_types=1);

namespace Mailcow\Scim\Service;

use Mailcow\Scim\Legacy\LegacyMailboxes;
use Mailcow\Scim\Model\Filter;
use Mailcow\Scim\Model\PatchOp;
use Mailcow\Scim\Model\Schema;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\Model\User;
use Mailcow\Scim\Repository\UserRepository;
use Mailcow\Scim\ScimError;

/**
 * SCIM Users (RFC 7644 3.3-3.6) on mailboxes with authsource 'scim'. Offboarding follows the IdP sync of mailcow:
 *
 * - active=false disallows the login (mailbox.active 2), mail is still delivered. active=true allows it again,
 *   but only when SCIM disallowed it: a state set by an admin wins.
 * - DELETE disallows the login too and removes the user from its SCIM groups and from SCIM: afterwards the id
 *   is unknown (RFC 7644 3.6). The mailbox and its mails are kept, deleting them is up to the admin.
 * - POST adopts a mailbox with authsource 'scim' that is no SCIM user (yet or again): the admin handed it over
 *   by choosing the authsource.
 *
 * userName is immutable: mailcow cannot rename mailboxes.
 */
class UserService
{
    public function __construct(private UserRepository $users, private LegacyMailboxes $legacy, private GroupService $groups)
    {
    }

    /** @return User[] */
    public function list(Token $token): array
    {
        return $this->users->all($token->domainRestriction);
    }

    /** @throws ScimError 404, also for users outside the token's domain */
    public function get(Token $token, string $id): User
    {
        return $this->users->find($id, $token->domainRestriction) ?? throw ScimError::notFound('User not found');
    }

    /** @throws ScimError */
    public function create(Token $token, array $body): User
    {
        Schema::requireSchema($body, Schema::USER);
        [$local, $domain] = self::userName($body['username'] ?? null);
        $username = $local . '@' . $domain;
        // checked first, so a restricted token cannot probe other domains
        if (!$token->covers($domain)) {
            throw new ScimError(403, "The token is restricted to the domain '{$token->domainRestriction}'");
        }
        $mailbox = $this->users->mailbox($username);
        if ($mailbox !== null && $mailbox['authsource'] !== 'scim') {
            throw ScimError::uniqueness("The mailbox '$username' uses the authentication source '{$mailbox['authsource']}': set it to SCIM in mailcow to hand it over");
        }
        if ($mailbox !== null && $mailbox['linked']) {
            throw ScimError::uniqueness("User '$username' already exists");
        }
        $externalId = self::externalId($body);
        if ($externalId !== null && $this->users->externalIdTaken($externalId)) {
            throw ScimError::uniqueness("externalId '$externalId' belongs to another user");
        }
        $name = self::name($body, $local);
        $active = array_key_exists('active', $body) ? Schema::bool($body['active']) : true;
        $template = $token->templateFor(self::templateAttribute($body));
        if ($mailbox === null) {
            $this->check($this->legacy->create($local, $domain, $name, $active ? 1 : 2, $template));
        } else {
            // adoption: the mailbox gets the template, then the name and state of the IdP (the template's own active must not win)
            if ($template !== null) {
                $this->check($this->legacy->applyTemplate($username, $name, $template));
            }
            $this->check($this->legacy->edit($username, ['name' => $name, 'active' => $active ? 1 : 2]));
        }
        $id = Schema::uuid();
        $this->users->link($id, $username, $externalId, $token->id, $template, $active ? 0 : 1);
        return $this->get($token, $id);
    }

    /** PUT: replaces the user; omitted attributes are cleared or get their defaults (RFC 7644 3.5.1) */
    public function replace(Token $token, string $id, array $body): User
    {
        $user = $this->get($token, $id);
        Schema::requireSchema($body, Schema::USER);
        if (!is_string($body['username'] ?? null) || trim($body['username']) === '') {
            throw ScimError::invalidValue('userName is required');
        }
        self::requireUserName($user, $body['username']);
        $template = $this->templateChange($token, $user, self::templateAttribute($body), false);
        $externalId = self::externalId($body);
        $active = array_key_exists('active', $body) ? Schema::bool($body['active']) : true;
        $this->save($user, self::name($body, strstr($user->username, '@', true)), $active, $externalId, $template);
        return $this->get($token, $id);
    }

    /** PATCH: all operations are validated before anything is written (RFC 7644 3.5.2 atomicity) */
    public function patch(Token $token, string $id, array $body): User
    {
        $user = $this->get($token, $id);
        [$given, $family] = array_pad(explode(' ', trim($user->name), 2), 2, '');
        $state = ['given' => $given, 'family' => $family, 'name' => false, 'active' => null,
            'externalId' => $user->externalId, 'template' => null];
        foreach (PatchOp::parse($body, 'User') as $op) {
            if ($op->ignored) {
                continue;
            }
            if ($op->path === null) {
                $this->patchObject($state, $op->op, $op->value, $user, $token);
            } else {
                $this->patchPath($state, $op->op, $op->path, $op->value, $user, $token);
            }
        }
        $name = null;
        if ($state['name']) {
            // mailbox('edit') keeps the name for '', so a cleared name becomes the local part like at creation
            $name = trim($state['given'] . ' ' . $state['family']) ?: strstr($user->username, '@', true);
        }
        $this->save($user, $name, $state['active'], $state['externalId'], $state['template']);
        return $this->get($token, $id);
    }

    /** DELETE: see the class description */
    public function delete(Token $token, string $id): void
    {
        $user = $this->get($token, $id);
        $this->groups->removeMember($user->username);
        if ($user->active === 1) {
            $this->check($this->legacy->edit($user->username, ['active' => 2]));
        }
        $this->users->unlink($user->username);
    }

    /**
     * Writes the changes of PUT and PATCH, after all checks. $template: template to apply to a user created
     * without one. $active null = unchanged.
     *
     * @throws ScimError
     */
    private function save(User $user, ?string $name, ?bool $active, ?string $externalId, ?string $template): void
    {
        if ($externalId !== null && $externalId !== $user->externalId && $this->users->externalIdTaken($externalId, $user->username)) {
            throw ScimError::uniqueness("externalId '$externalId' belongs to another user");
        }
        $fields = [];
        $map = ($externalId !== $user->externalId) ? ['external_id' => $externalId] : [];
        if ($template !== null) {
            $this->check($this->legacy->applyTemplate($user->username, $name ?? $user->name, $template));
            $map['template'] = $template;
        }
        if ($name !== null && $name !== $user->name) {
            $fields['name'] = $name;
        }
        if ($active === false && $user->active === 1 && $user->disabled === 0) {
            $fields['active'] = 2;
            $map['disabled'] = 1;
        } elseif ($active === true && $user->disabled === 1) {
            if ($user->active === 2) {
                $fields['active'] = 1;
            }
            $map['disabled'] = 0;
        }
        if ($fields !== []) {
            $this->check($this->legacy->edit($user->username, $fields));
        }
        $this->users->update($user->username, $map);
    }

    /** One operation without path: its value is an object of attributes (keys lowercased) */
    private function patchObject(array &$state, string $op, array $value, User $user, Token $token): void
    {
        foreach ($value as $key => $v) {
            $key = (string)$key;
            if ($key === strtolower(Schema::USER)) {
                $this->patchObject($state, $op, self::object($v, 'Schema value'), $user, $token);
            } elseif ($key === strtolower(Schema::EXT)) {
                $state['template'] = $this->templateChange($token, $user, self::templateValue(self::object($v, 'Extension value')), false) ?? $state['template'];
            } elseif (in_array($key, Schema::IGNORED, true) || $key === 'schemas' || $key === 'meta') {
                continue;
            } elseif ($key === 'id') {
                if (!is_string($v) || $v !== $user->scimId) {
                    throw ScimError::mutability("'id' is read-only");
                }
            } elseif (str_contains($key, '.') || str_contains($key, '[') || str_contains($key, ':')) {
                // Entra ID sends path-less operations with paths as keys: {"name.givenName": "x"}
                $path = Filter::path($key, 'User');
                if ($path !== null) {
                    $this->patchPath($state, $op, $path, $v, $user, $token);
                }
            } elseif (Schema::attribute('User', $key) !== null) {
                $this->patchPath($state, $op, ['attr' => Schema::attribute('User', $key), 'filter' => null, 'sub' => null], $v, $user, $token);
            } else {
                throw new ScimError(400, "Unknown attribute '$key'", 'invalidPath');
            }
        }
    }

    /** One operation on a parsed path */
    private function patchPath(array &$state, string $op, array $path, mixed $value, User $user, Token $token): void
    {
        $attr = $path['attr'];
        if ($attr['ext']) {
            if ($op === 'remove') {
                $this->templateChange($token, $user, null, true);
                return;
            }
            $template = ($attr['parts'] === ['template']) ? self::text($value, 'template') : self::templateValue(self::object($value, 'Extension value'));
            $state['template'] = $this->templateChange($token, $user, ($template === '') ? null : $template, false) ?? $state['template'];
            return;
        }
        $sub = $attr['parts'][1] ?? $path['sub'];
        switch ($attr['parts'][0]) {
            case 'username':
                if ($op === 'remove') {
                    throw ScimError::mutability('userName cannot be removed');
                }
                self::requireUserName($user, $value);
                return;
            case 'displayname':
                self::setName($state, ($op === 'remove') ? '' : self::text($value, 'displayName'));
                return;
            case 'name':
                if ($sub === null && $op !== 'remove') {
                    $this->patchObject($state, $op, self::prefixed(self::object($value, "'name'")), $user, $token);
                    return;
                }
                $text = ($op === 'remove') ? '' : self::text($value, 'name');
                if ($sub === null || $sub === 'formatted') {
                    self::setName($state, $text);
                } else {
                    $state[($sub === 'givenname') ? 'given' : 'family'] = $text;
                    $state['name'] = true;
                }
                return;
            case 'active':
                if ($op === 'remove') {
                    throw ScimError::invalidValue("'active' cannot be removed");
                }
                $state['active'] = Schema::bool($value);
                return;
            case 'externalid':
                $state['externalId'] = ($op === 'remove' || $value === null) ? null : self::text($value, 'externalId');
                return;
            case 'emails':
                self::checkEmails($user, $op, $value, $sub);
                return;
            case 'id':
                throw ScimError::mutability("'id' is read-only");
            default:
                // schemas, meta: server-controlled, ignored
                return;
        }
    }

    /**
     * Template to record for a user created without one (it is applied then), null when nothing changes.
     *
     * @throws ScimError mutability: the template is applied at creation only
     */
    private function templateChange(Token $token, User $user, ?string $attribute, bool $remove): ?string
    {
        if ($remove) {
            if ($user->template !== null) {
                throw ScimError::mutability("'template' is immutable and cannot be removed");
            }
            return null;
        }
        if ($attribute === null) {
            return null;
        }
        $resolved = $token->templateFor($attribute);
        if ($user->template === null) {
            return $resolved;
        }
        // GET-modify-PUT round trips send back the applied template name, not the mapped value
        if ($resolved !== $user->template && $attribute !== $user->template) {
            throw ScimError::mutability("'template' is immutable, it is applied at creation only");
        }
        return null;
    }

    /** @throws ScimError for a mailcow error */
    private function check(?string $error): void
    {
        if ($error !== null) {
            throw ScimError::invalidValue('mailcow rejected the operation: ' . $error);
        }
    }

    /**
     * Local part and domain of a userName, normalized like mailbox('add') does (IDN domains in punycode).
     *
     * @return array{0: string, 1: string}
     */
    private static function userName(mixed $value): array
    {
        $value = is_string($value) ? trim($value) : '';
        $at = strrpos($value, '@');
        $local = ($at === false) ? '' : strtolower(substr($value, 0, $at));
        $domain = ($at === false) ? false : idn_to_ascii(strtolower(substr($value, $at + 1)), 0, INTL_IDNA_VARIANT_UTS46);
        if ($local === '' || !is_string($domain) || !filter_var($local . '@' . $domain, FILTER_VALIDATE_EMAIL)) {
            throw ScimError::invalidValue('userName must be a valid email address');
        }
        return [$local, $domain];
    }

    private static function requireUserName(User $user, mixed $value): void
    {
        if (!is_string($value) || strcasecmp(trim($value), $user->username) !== 0) {
            throw ScimError::mutability('userName is immutable: mailcow cannot rename mailboxes');
        }
    }

    /** Name of a User body: displayName, else name.formatted, else givenName + familyName, else $default */
    private static function name(array $body, string $default): string
    {
        $name = is_array($body['name'] ?? null) ? $body['name'] : [];
        foreach ([$body['displayname'] ?? null, $name['formatted'] ?? null] as $value) {
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }
        $full = trim(self::text($name['givenname'] ?? '', 'givenName') . ' ' . self::text($name['familyname'] ?? '', 'familyName'));
        return ($full !== '') ? $full : $default;
    }

    private static function setName(array &$state, string $full): void
    {
        [$state['given'], $state['family']] = array_pad(explode(' ', trim($full), 2), 2, '');
        $state['name'] = true;
    }

    private static function externalId(array $body): ?string
    {
        $value = $body['externalid'] ?? null;
        return ($value === null) ? null : self::text($value, 'externalId');
    }

    /** The extension attribute `template` of a User body */
    private static function templateAttribute(array $body): ?string
    {
        $ext = $body[strtolower(Schema::EXT)] ?? null;
        return is_array($ext) ? self::templateValue($ext) : null;
    }

    private static function templateValue(?array $ext): ?string
    {
        $value = $ext['template'] ?? null;
        return (is_string($value) && trim($value) !== '') ? trim($value) : null;
    }

    /** emails are derived from userName: only a modification that keeps the address is accepted */
    private static function checkEmails(User $user, string $op, mixed $value, ?string $sub): void
    {
        if ($op === 'remove') {
            throw ScimError::mutability("'emails' is read-only (derived from userName)");
        }
        if ($sub !== null && $sub !== 'value') {
            return; // type/primary of the single address, nothing to store
        }
        $items = (is_array($value) && array_is_list($value)) ? $value : [$value];
        foreach ($items as $item) {
            $address = is_array($item) ? ($item['value'] ?? null) : $item;
            if ($address === null && is_array($item)) {
                continue;
            }
            if (!is_string($address) || strcasecmp(trim($address), $user->username) !== 0) {
                throw ScimError::mutability("'emails' is read-only (derived from userName), and mailcow cannot rename mailboxes");
            }
        }
    }

    /** Scalar as trimmed string */
    private static function text(mixed $value, string $attribute): string
    {
        if (!is_scalar($value)) {
            throw ScimError::invalidValue("'$attribute' must be a string");
        }
        return trim((string)$value);
    }

    /** @throws ScimError unless $value is a JSON object */
    private static function object(mixed $value, string $what): array
    {
        if (is_array($value) && ($value === [] || !array_is_list($value))) {
            return $value;
        }
        throw ScimError::invalidValue("$what must be a complex object");
    }

    /** {"givenname": x} => {"name.givenname": x}: the stored sub-attributes of `name` as paths, others are ignored */
    private static function prefixed(array $name): array
    {
        $out = [];
        foreach (['formatted', 'givenname', 'familyname'] as $key) {
            if (array_key_exists($key, $name)) {
                $out['name.' . $key] = $name[$key];
            }
        }
        return $out;
    }
}
