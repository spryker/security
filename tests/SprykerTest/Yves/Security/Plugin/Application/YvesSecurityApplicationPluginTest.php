<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Yves\Security\Plugin\Application;

use Codeception\Test\Unit;
use ReflectionClass;
use Spryker\Shared\Security\Configuration\SecurityConfiguration;
use Spryker\Shared\Security\Exception\AuthenticationEntryNotRegisteredException;
use Spryker\Yves\Security\Configurator\SecurityConfigurator;
use Spryker\Yves\Security\Plugin\Application\YvesSecurityApplicationPlugin;
use SprykerTest\Yves\Security\Fixtures\DefaultAuthenticator;
use Symfony\Component\BrowserKit\AbstractBrowser;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Auto-generated group annotations
 *
 * @group SprykerTest
 * @group Yves
 * @group Security
 * @group Plugin
 * @group Application
 * @group YvesSecurityApplicationPluginTest
 * Add your own group annotations below this line
 */
class YvesSecurityApplicationPluginTest extends Unit
{
    /**
     * @var string
     */
    protected const TEST_SECURITY_AUTHENTICATION_LISTENER_FACTORY_TYPE = 'test_security_type';

    /**
     * @var string
     */
    protected const TEST_SECURITY_AUTHENTICATION_LISTENER_FACTORY = 'security.authentication_listener.factory.test_security_type';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_TOKEN_STORAGE = 'security.token_storage';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHORIZATION_CHECKER = 'security.authorization_checker';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_LAST_ERROR = 'security.last_error';

    /**
     * @var string
     */
    protected const SERVICE_SESSION = 'session';

    /**
     * @var string
     */
    protected const SECURITY_DEFAULT_LOGIN_FORM_AUTHENTICATOR = 'security.default.login_form.authenticator';

    /**
     * @var string
     */
    protected const ADMIN = 'ADMIN';

    /**
     * @var string
     */
    protected const ACCESS_MODE_PUBLIC = 'PUBLIC_ACCESS';

    /**
     * @var string
     */
    protected const IS_AUTHENTICATED_FULLY = 'IS_AUTHENTICATED_FULLY';

    /**
     * @var string
     */
    protected const AUTHENTICATED = 'AUTHENTICATED';

    /**
     * @var string
     */
    protected const ROLE_ADMIN = 'ROLE_ADMIN';

    /**
     * @var string
     */
    protected const ROLE_USER = 'ROLE_USER';

    /**
     * @var string
     */
    protected const FAKE_PASSWORD = '$2y$04$5kJ3kQpVZkH.x7ydtxPqTu/tRUlrFPGuByNj4.UVE6uhfWpnVxaUq';

    /**
     * @var string
     */
    protected const HTTP_AUTH_FIREWALL_NAME = 'http-auth';

    /**
     * @var string
     */
    protected const LOGIN_FIREWALL_NAME = 'login';

    /**
     * @var string
     */
    protected const DEFAULT_FIREWALL_NAME = 'default';

    protected const string USER_NAME = 'user';

    protected const string USER_PASSWORD = 'foo';

    protected const string USER_INVALID_PASSWORD = 'bar';

    protected const string ADMIN_NAME = 'admin';

    protected const string PARAMETER_SWITCH_USER = '_switch_user';

    protected const string SWITCH_USER_EXIT_VALUE = '_exit';

    protected const int LOGIN_SUCCESS_SUBSCRIBER_PRIORITY = 1;

    protected const string SERVICE_DISPATCHER = 'dispatcher';

    protected const string CSRF_TOKEN_SESSION_KEY = '_csrf/test_form';

    protected const string PLANTED_CSRF_TOKEN = 'planted-csrf-token';

    protected const string LOGIN_FORM_NAME = 'loginForm';

    protected const string INVALID_CSRF_TOKEN = 'invalid-csrf-token';

    /**
     * @var \SprykerTest\Yves\Security\SecurityTester
     */
    protected $tester;

    /**
     * @var \Spryker\Yves\Security\Plugin\Application\SecurityApplicationPlugin|null
     */
    protected $securityApplicationPlugin;

    protected function setUp(): void
    {
        parent::setUp();

        if ($this->tester->isSymfonyVersion5() === true) {
            $this->markTestSkipped('Compatible only with `symfony/security-core` package version >= 6. Will be enabled by default once Symfony 5 support is discontinued.');
        }
    }

    public function testProvideAddsAllServices(): void
    {
        //Arrange
        $container = $this->tester->getContainer();
        $securityApplicationPlugin = new YvesSecurityApplicationPlugin();

        //Act
        $securityApplicationPlugin->provide($container);

        //Assert
        $this->assertTrue($container->has('security.firewall'));
    }

    /**
     * @group testWrongAuthenticationType
     *
     * @return void
     */
    public function testWrongAuthenticationType(): void
    {
        //Arrange
        $securityConfiguration = new SecurityConfiguration();
        $securityConfiguration->addFirewall('wrong', [
            'foobar' => true,
            'users' => [],
        ]);
        $this->tester->mockYvesSecurityPlugin($securityConfiguration);
        $this->tester->mockSecurityDependencies();
        $this->tester->enableSecurityApplicationPlugin();

        //Assert
        $this->expectException(AuthenticationEntryNotRegisteredException::class);

        //Act
        $this->tester->getKernel()->handle(Request::create('/'));
    }

    public function testFormAuthentication(): void
    {
        //Arrange
        $this->addFormAuthentication();

        $container = $this->tester->getContainer();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();

        //Act
        $httpKernelBrowser->restart();
        $httpKernelBrowser->request('get', '/');

        //Assert
        $this->assertSame(static::ACCESS_MODE_PUBLIC, $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => 'user', 'password' => 'bar']]);
        $this->assertSame(403, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('{"message":"Invalid credentials."}', $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->getRequest()->getSession()->start();

        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => 'user', 'password' => 'foo']]);
        $this->assertNull($container->get(static::SERVICE_SECURITY_LAST_ERROR)($httpKernelBrowser->getRequest()));
        $httpKernelBrowser->getRequest()->getSession()->save();
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('http://localhost/', $httpKernelBrowser->getResponse()->getTargetUrl());

        $httpKernelBrowser->request('get', '/');
        $this->assertSame('userAUTHENTICATED', $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->request('get', '/logout');
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('http://localhost/', $httpKernelBrowser->getResponse()->getTargetUrl());

        $httpKernelBrowser->request('get', '/');
        $this->assertSame(static::ACCESS_MODE_PUBLIC, $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->request('get', '/admin');

        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('http://localhost/login', $httpKernelBrowser->getResponse()->getTargetUrl());

        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => 'admin', 'password' => 'foo']]);
        $this->assertNull($container->get(static::SERVICE_SECURITY_LAST_ERROR)($httpKernelBrowser->getRequest()));

        $httpKernelBrowser->getRequest()->getSession()->save();

        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('http://localhost/admin', $httpKernelBrowser->getResponse()->getTargetUrl());

        $httpKernelBrowser->request('get', '/');
        $this->assertSame('adminAUTHENTICATEDADMIN', $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->request('get', '/admin');
        $this->assertSame(static::ADMIN, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testFormAuthenticationRegeneratesSessionIdOnSuccessfulLogin(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $preLoginSessionId = $this->startSessionWithCookie($httpKernelBrowser);

        // Act
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

        // Assert
        $postLoginSessionId = $httpKernelBrowser->getRequest()->getSession()->getId();

        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertNotSame($preLoginSessionId, $postLoginSessionId, 'Expected a new session id after a successful login.');

        $httpKernelBrowser->request('get', '/');
        $this->assertSame(static::USER_NAME . static::AUTHENTICATED, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testFormAuthenticationKeepsSessionIdOnFailedLogin(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $preLoginSessionId = $this->startSessionWithCookie($httpKernelBrowser);

        // Act
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_INVALID_PASSWORD]]);

        // Assert
        $this->assertSame(403, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame($preLoginSessionId, $httpKernelBrowser->getRequest()->getSession()->getId());
    }

    public function testLoginSuccessSubscribersReadTheNewSessionId(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $preLoginSessionId = $this->startSessionWithCookie($httpKernelBrowser);
        $sessionIdSeenBySubscriber = null;
        $this->tester->getContainer()->get(static::SERVICE_DISPATCHER)->addListener(
            LoginSuccessEvent::class,
            function (LoginSuccessEvent $loginSuccessEvent) use (&$sessionIdSeenBySubscriber): void {
                $sessionIdSeenBySubscriber = $loginSuccessEvent->getRequest()->getSession()->getId();
            },
            static::LOGIN_SUCCESS_SUBSCRIBER_PRIORITY,
        );

        // Act
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

        // Assert
        $this->assertNotSame($preLoginSessionId, $sessionIdSeenBySubscriber);
        $this->assertSame($httpKernelBrowser->getRequest()->getSession()->getId(), $sessionIdSeenBySubscriber);
    }

    public function testFormAuthenticationClearsCsrfTokensOnSuccessfulLogin(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $this->startSessionWithCookie($httpKernelBrowser, [static::CSRF_TOKEN_SESSION_KEY => static::PLANTED_CSRF_TOKEN]);

        // Act
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertFalse($httpKernelBrowser->getRequest()->getSession()->has(static::CSRF_TOKEN_SESSION_KEY), 'Expected the pre-login CSRF tokens to be removed after a successful login.');
    }

    public function testFormAuthenticationWithValidCsrfTokenLogsUserIn(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $this->tester->getContainer()->get(static::SERVICE_SESSION)->start();
        $csrfToken = $this->tester->addFormCsrfProvider()->getToken(static::LOGIN_FORM_NAME)->getValue();

        // Act
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD, '_token' => $csrfToken]]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
    }

    public function testFormAuthenticationWithInvalidCsrfTokenFails(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $this->tester->getContainer()->get(static::SERVICE_SESSION)->start();
        $this->tester->addFormCsrfProvider();

        // Act
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD, '_token' => static::INVALID_CSRF_TOKEN]]);

        // Assert
        $this->assertSame(403, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('{"message":"Invalid CSRF token."}', $httpKernelBrowser->getResponse()->getContent());
    }

    /**
     * On Yves the switch-user rotation belongs to SessionAgentValidation, which rotates the session and re-saves the
     * agent session ID in one step. If Security rotated here as well, a project upgrading Security alone would keep a
     * stale agent session ID and the agent would be logged out on every impersonation start.
     */
    public function testSwitchUserKeepsSessionIdOnImpersonationStart(): void
    {
        // Arrange
        $httpKernelBrowser = $this->loginAsAdminWithSwitchUser();
        $preSwitchSessionId = $httpKernelBrowser->getRequest()->getSession()->getId();

        // Act
        $httpKernelBrowser->request('get', '/', [static::PARAMETER_SWITCH_USER => static::USER_NAME]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame($preSwitchSessionId, $httpKernelBrowser->getRequest()->getSession()->getId());

        $httpKernelBrowser->request('get', '/');
        $this->assertSame(static::USER_NAME . static::AUTHENTICATED, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testSwitchUserKeepsSessionIdOnImpersonationEnd(): void
    {
        // Arrange
        $httpKernelBrowser = $this->loginAsAdminWithSwitchUser();
        $httpKernelBrowser->request('get', '/', [static::PARAMETER_SWITCH_USER => static::USER_NAME]);
        $impersonationSessionId = $httpKernelBrowser->getRequest()->getSession()->getId();

        // Act
        $httpKernelBrowser->request('get', '/', [static::PARAMETER_SWITCH_USER => static::SWITCH_USER_EXIT_VALUE]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame($impersonationSessionId, $httpKernelBrowser->getRequest()->getSession()->getId());

        $httpKernelBrowser->request('get', '/');
        $this->assertSame(static::ADMIN_NAME . static::AUTHENTICATED . static::ADMIN, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testFormAuthenticationThrowsExceptionOnRestrictedAction(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->restart();
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => 'user', 'password' => 'foo']]);

        // Assert
        $this->expectException(AccessDeniedHttpException::class);

        // Act
        $httpKernelBrowser->request('get', '/admin');
    }

    public function testHttpAuthentication(): void
    {
        //Arrange
        $this->addHttpAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->restart();

        //Act
        $httpKernelBrowser->request('get', '/', [], [], ['PHP_AUTH_USER' => 'user', 'PHP_AUTH_PW' => 'foo']);

        //Assert
        $this->assertSame('userAUTHENTICATED', $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->restart();

        $httpKernelBrowser->request('get', '/', [], [], ['PHP_AUTH_USER' => 'admin', 'PHP_AUTH_PW' => 'foo']);
        $this->assertSame('adminAUTHENTICATEDADMIN', $httpKernelBrowser->getResponse()->getContent());
        $httpKernelBrowser->request('get', '/admin');
        $this->assertSame(static::ADMIN, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testHttpAuthenticationThrowsExceptionOnRestrictedAction(): void
    {
        // Arrange
        $this->addHttpAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->restart();
        $httpKernelBrowser->request('get', '/', [], [], ['PHP_AUTH_USER' => 'user', 'PHP_AUTH_PW' => 'foo']);

        // Assert
        $this->expectException(AccessDeniedHttpException::class);

        // Act
        $httpKernelBrowser->request('get', '/admin');
    }

    /**
     * @param array<string, mixed> $additionalFirewallOptions
     */
    protected function addFormAuthentication(array $additionalFirewallOptions = []): void
    {
        $securityConfiguration = new SecurityConfiguration();
        $securityConfiguration
            ->addFirewall(static::LOGIN_FIREWALL_NAME, [
                'pattern' => '^/login$',
            ])
            ->addFirewall(static::DEFAULT_FIREWALL_NAME, [
                'pattern' => '^.*$',
                'form' => [
                    'require_previous_session' => false,
                    'authenticators' => [
                        static::SECURITY_DEFAULT_LOGIN_FORM_AUTHENTICATOR,
                    ],
                ],
                'logout' => true,
                'users' => [
                    // password is foo
                    'user' => [static::ROLE_USER, static::FAKE_PASSWORD],
                    'admin' => [static::ROLE_ADMIN, static::FAKE_PASSWORD],
                ],
            ] + $additionalFirewallOptions)
            ->addAccessRules([['^/admin', static::ROLE_ADMIN]])
            ->addRoleHierarchy([static::ROLE_ADMIN => [static::ROLE_USER]]);

        $this->tester->mockSecurityDependencies();
        $this->tester->mockYvesSecurityPlugin($securityConfiguration);
        $this->tester->enableSecurityApplicationPlugin();

        $container = $this->tester->getContainer();
        $container->set(static::SECURITY_DEFAULT_LOGIN_FORM_AUTHENTICATOR, function () {
            return new DefaultAuthenticator();
        });

        $this->tester->addRoute('login', '/login', function (Request $request) use ($container) {
            $container->get(static::SERVICE_SESSION)->start();
            $securityLastError = $container->get(static::SERVICE_SECURITY_LAST_ERROR);

            return $securityLastError($request);
        });

        $this->tester->addRoute('logout', '/logout', function (Request $request) use ($container) {
            $container->get(static::SERVICE_SESSION)->stop();
            $securityLastError = $container->get(static::SERVICE_SECURITY_LAST_ERROR);

            return $securityLastError($request);
        });

        $this->tester->addRoute('homepage', '/', function () use ($container) {
            $token = $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE)->getToken();
            $content = $token ? $token->getUser()->getUserIdentifier() : static::ACCESS_MODE_PUBLIC;

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::IS_AUTHENTICATED_FULLY)) {
                $content .= static::AUTHENTICATED;
            }

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::ROLE_ADMIN)) {
                $content .= static::ADMIN;
            }

            return new Response($content);
        });

        $this->tester->addRoute('admin', '/admin', function () {
            return new Response(static::ADMIN);
        });
    }

    protected function loginAsAdminWithSwitchUser(): AbstractBrowser
    {
        $this->addFormAuthentication([
            'switch_user' => [
                'parameter' => static::PARAMETER_SWITCH_USER,
                'role' => static::ROLE_ADMIN,
            ],
        ]);
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $this->startSessionWithCookie($httpKernelBrowser);
        $httpKernelBrowser->request('post', '/login_check', ['loginForm' => ['username' => static::ADMIN_NAME, 'password' => static::USER_PASSWORD]]);

        return $httpKernelBrowser;
    }

    /**
     * @param array<string, string> $sessionAttributes
     */
    protected function startSessionWithCookie(AbstractBrowser $httpKernelBrowser, array $sessionAttributes = []): string
    {
        $httpKernelBrowser->request('get', '/');
        $session = $httpKernelBrowser->getRequest()->getSession();
        $session->start();

        foreach ($sessionAttributes as $name => $value) {
            $session->set($name, $value);
        }

        $httpKernelBrowser->getCookieJar()->set(new Cookie($session->getName(), $session->getId()));
        $session->save();

        return $session->getId();
    }

    protected function addHttpAuthentication(): void
    {
        $securityConfiguration = new SecurityConfiguration();
        $securityConfiguration
            ->addFirewall(static::HTTP_AUTH_FIREWALL_NAME, [
                'pattern' => '^.*$',
                'http' => true,
                'users' => [
                    // password is foo
                    'user' => [static::ROLE_USER, static::FAKE_PASSWORD],
                    'admin' => [static::ROLE_ADMIN, static::FAKE_PASSWORD],
                ],
            ])
            ->addAccessRules([['^/admin', static::ROLE_ADMIN]])
            ->addRoleHierarchy([static::ROLE_ADMIN => [static::ROLE_USER]]);

        $this->tester->mockYvesSecurityPlugin($securityConfiguration);
        $this->tester->mockSecurityDependencies();
        $this->tester->enableSecurityApplicationPlugin();

        $this->tester->addRoute('homepage', '/', function () {
            $container = $this->tester->getContainer();

            if (!$container->has(static::SERVICE_SECURITY_TOKEN_STORAGE)) {
                return new Response(static::ACCESS_MODE_PUBLIC);
            }

            $token = $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE)->getToken();
            $content = $token->getUser()->getUserIdentifier();

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::IS_AUTHENTICATED_FULLY)) {
                $content .= static::AUTHENTICATED;
            }

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::ROLE_ADMIN)) {
                $content .= static::ADMIN;
            }

            return new Response($content);
        });

        $this->tester->addRoute('admin', '/admin', function () {
            return new Response(static::ADMIN);
        });
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        $reflection = new ReflectionClass(SecurityConfigurator::class);
        $property = $reflection->getProperty('securityConfiguration');
        $property->setValue(null);
    }
}
