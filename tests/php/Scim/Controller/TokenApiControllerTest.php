<?php

declare(strict_types=1);

namespace Mailcow\Tests\Scim\Controller;

use Mailcow\Core\AccessDenied;
use Mailcow\Core\ApiResponse;
use Mailcow\Scim\Controller\TokenApiController;
use Mailcow\Scim\Model\Token;
use Mailcow\Scim\Service\TokenService;
use PHPUnit\Framework\TestCase;

class TokenApiControllerTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
    }

    public function testTheNewTokenIsOnlyInTheSession(): void
    {
        $service = $this->createMock(TokenService::class);
        $service->method('create')->willReturn([Token::fromRow(['id' => 3, 'description' => 'Entra']), 'secret-value']);

        $this->assertTrue((new TokenApiController($service, new ApiResponse()))->addToken(['description' => 'Entra']));
        $this->assertSame('secret-value', $_SESSION['scim_new_token']);
        $this->assertSame([['type' => 'success', 'log' => ['scim', 'add', 'token', ['description' => 'Entra']],
            'msg' => ['scim_token_added', 'Entra']]], $_SESSION['return']);
        $this->assertStringNotContainsString('secret-value', json_encode($_SESSION['return']));
    }

    public function testOneMessagePerId(): void
    {
        $service = $this->createMock(TokenService::class);
        $service->method('delete')->willReturnCallback(fn(int $id): Token => ($id === 3) ? Token::fromRow(['id' => 3]) : throw new AccessDenied());

        (new TokenApiController($service, new ApiResponse()))->deleteTokens(['3', '4', 'x']);
        $this->assertSame(['success', 'danger', 'danger'], array_column($_SESSION['return'], 'type'));
        $this->assertSame(['scim_token_deleted', '3'], $_SESSION['return'][0]['msg']);
    }
}
