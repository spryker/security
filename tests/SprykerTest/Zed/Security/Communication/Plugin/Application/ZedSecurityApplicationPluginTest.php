<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Security\Communication\Plugin\Application;

use Codeception\Test\Unit;
use ReflectionClass;
use Spryker\Shared\Security\Configuration\SecurityConfiguration;
use Spryker\Shared\Security\Exception\AuthenticationEntryNotRegisteredException;
use Spryker\Zed\Security\Communication\Configurator\SecurityConfigurator;
use Spryker\Zed\Security\Communication\Plugin\Application\ZedSecurityApplicationPlugin;
use SprykerTest\Zed\Security\Fixtures\DefaultAuthenticator;
use Symfony\Component\BrowserKit\AbstractBrowser;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\SecurityEvents;

/**
 * Auto-generated group annotations
 *
 * @group SprykerTest
 * @group Zed
 * @group Security
 * @group Communication
 * @group Plugin
 * @group Application
 * @group ZedSecurityApplicationPluginTest
 * Add your own group annotations below this line
 */
class ZedSecurityApplicationPluginTest extends Unit
{
    /**
     * @var string
     */
    protected const SERVICE_SECURITY_FIREWALL = 'security.firewall';

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
    protected const SERVICE_SECURITY_TOKEN_STORAGE = 'security.token_storage';

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
    protected const HOMEPAGE_PATH = '/homepage';

    /**
     * @var string
     */
    protected const USER_PAGE_PATH = '/homepage/user';

    /**
     * @var string
     */
    protected const LOGIN_PATH = '/login';

    /**
     * @var string
     */
    protected const USER_NAME = 'user';

    /**
     * @var string
     */
    protected const USER_PASSWORD = 'foo';

    /**
     * @var string
     */
    protected const USER_ENCODED_PASSWORD = '$2y$04$5kJ3kQpVZkH.x7ydtxPqTu/tRUlrFPGuByNj4.UVE6uhfWpnVxaUq';

    /**
     * @var string
     */
    protected const USER_INVALID_PASSWORD = 'bar';

    /**
     * @var string
     */
    protected const ROLE_USER = 'ROLE_USER';

    /**
     * @var string
     */
    protected const USER = 'USER';

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
    protected const HTTP_AUTH_FIREWALL_NAME = 'http-auth';

    protected const string TARGET_USER_NAME = 'target-user';

    protected const string PARAMETER_SWITCH_USER = '_switch_user';

    protected const string SWITCH_USER_EXIT_VALUE = '_exit';

    protected const int SWITCH_USER_SUBSCRIBER_PRIORITY = 1;

    protected const int LOGIN_SUCCESS_SUBSCRIBER_PRIORITY = 1;

    protected const string SERVICE_DISPATCHER = 'dispatcher';

    protected const string CSRF_TOKEN_SESSION_KEY = '_csrf/test_form';

    protected const string PLANTED_CSRF_TOKEN = 'planted-csrf-token';

    /**
     * @var \SprykerTest\Zed\Security\SecurityCommunicationTester
     */
    protected $tester;

    protected function setUp(): void
    {
        parent::setUp();

        if ($this->tester->isSymfonyVersion5() === true) {
            $this->markTestSkipped('Compatible only with `symfony/security-core` package version >= 6. Will be enabled by default once Symfony 5 support is discontinued.');
        }
    }

    public function testProvideAddsAllServices(): void
    {
        // Arrange
        $container = $this->tester->getContainer();
        $securityApplicationPlugin = new ZedSecurityApplicationPlugin();

        // Act
        $securityApplicationPlugin->provide($container);

        // Assert
        $this->assertTrue($container->has(static::SERVICE_SECURITY_FIREWALL));
    }

    /**
     * @group testZedWrongAuthenticationType
     *
     * @return void
     */
    public function testWrongAuthenticationType(): void
    {
        // Arrange
        $securityConfiguration = new SecurityConfiguration();
        $securityConfiguration->addFirewall('wrong', [
            'foobar' => true,
            'users' => [],
        ]);
        $this->tester->mockZedSecurityPlugin($securityConfiguration);
        $this->tester->mockSecurityDependencies();
        $this->tester->enableSecurityApplicationPlugin();

        // Assert
        $this->expectException(AuthenticationEntryNotRegisteredException::class);

        // Act
        $this->tester->getKernel()->handle(Request::create(static::HOMEPAGE_PATH));
    }

    public function testFormAuthentication(): void
    {
        //Arrange
        $this->addFormAuthentication();
        $container = $this->tester->getContainer();

        //Act
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);

        //Assert
        $this->assertSame(static::ACCESS_MODE_PUBLIC, $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_INVALID_PASSWORD]]);
        $this->assertSame(403, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('{"message":"Invalid credentials."}', $httpKernelBrowser->getResponse()->getContent());

        $httpKernelBrowser->getRequest()->getSession()->start();

        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);
        $this->assertNull($container->get(static::SERVICE_SECURITY_LAST_ERROR)($httpKernelBrowser->getRequest()));

        $httpKernelBrowser->getRequest()->getSession()->save();

        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('http://localhost/', $httpKernelBrowser->getResponse()->getTargetUrl());
    }

    public function testFormAuthenticationRegeneratesSessionIdOnSuccessfulLogin(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $preLoginSessionId = $this->startSessionWithCookie($httpKernelBrowser);

        // Act
        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

        // Assert
        $postLoginSessionId = $httpKernelBrowser->getRequest()->getSession()->getId();

        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertNotSame($preLoginSessionId, $postLoginSessionId, 'Expected a new session id after a successful login.');

        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);
        $this->assertSame(static::USER_NAME, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testFormAuthenticationKeepsSessionIdOnFailedLogin(): void
    {
        // Arrange
        $this->addFormAuthentication();
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $preLoginSessionId = $this->startSessionWithCookie($httpKernelBrowser);

        // Act
        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_INVALID_PASSWORD]]);

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
        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

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
        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertFalse($httpKernelBrowser->getRequest()->getSession()->has(static::CSRF_TOKEN_SESSION_KEY), 'Expected the pre-login CSRF tokens to be removed after a successful login.');
    }

    public function testSwitchUserRegeneratesSessionIdOnImpersonationStart(): void
    {
        // Arrange
        $httpKernelBrowser = $this->loginWithSwitchUser();
        $preSwitchSessionId = $httpKernelBrowser->getRequest()->getSession()->getId();

        // Act
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH, [static::PARAMETER_SWITCH_USER => static::TARGET_USER_NAME]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertNotSame($preSwitchSessionId, $httpKernelBrowser->getRequest()->getSession()->getId(), 'Expected a new session id after the impersonation start.');

        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);
        $this->assertSame(static::TARGET_USER_NAME, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testSwitchUserRegeneratesSessionIdOnImpersonationEnd(): void
    {
        // Arrange
        $httpKernelBrowser = $this->loginWithSwitchUser();
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH, [static::PARAMETER_SWITCH_USER => static::TARGET_USER_NAME]);
        $impersonationSessionId = $httpKernelBrowser->getRequest()->getSession()->getId();

        // Act
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH, [static::PARAMETER_SWITCH_USER => static::SWITCH_USER_EXIT_VALUE]);

        // Assert
        $this->assertSame(302, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertNotSame($impersonationSessionId, $httpKernelBrowser->getRequest()->getSession()->getId(), 'Expected a new session id after the impersonation end.');

        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);
        $this->assertSame(static::USER_NAME, $httpKernelBrowser->getResponse()->getContent());
    }

    public function testSwitchUserSubscribersReadTheNewSessionId(): void
    {
        // Arrange
        $httpKernelBrowser = $this->loginWithSwitchUser();
        $sessionIdSeenBySubscriber = null;
        $this->tester->getContainer()->get(static::SERVICE_DISPATCHER)->addListener(
            SecurityEvents::SWITCH_USER,
            function (SwitchUserEvent $switchUserEvent) use (&$sessionIdSeenBySubscriber): void {
                $sessionIdSeenBySubscriber = $switchUserEvent->getRequest()->getSession()->getId();
            },
            static::SWITCH_USER_SUBSCRIBER_PRIORITY,
        );

        // Act
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH, [static::PARAMETER_SWITCH_USER => static::TARGET_USER_NAME]);

        // Assert
        $this->assertSame($httpKernelBrowser->getRequest()->getSession()->getId(), $sessionIdSeenBySubscriber);
    }

    public function testHttpAuthentication(): void
    {
        //Arrange
        $this->addHttpAuthentication();

        //Act
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);

        //Assert
        $this->assertSame(401, $httpKernelBrowser->getResponse()->getStatusCode());
        $this->assertSame('Basic realm="Secured"', $httpKernelBrowser->getResponse()->headers->get('www-authenticate'));

        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH, [], [], ['PHP_AUTH_USER' => static::USER_NAME, 'PHP_AUTH_PW' => static::USER_PASSWORD]);
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);

        $this->assertSame('userAUTHENTICATEDUSER', $httpKernelBrowser->getResponse()->getContent());
    }

    /**
     * @param array<string, mixed> $additionalFirewallOptions
     */
    protected function addFormAuthentication(array $additionalFirewallOptions = []): void
    {
        $securityConfiguration = new SecurityConfiguration();
        $securityConfiguration
            ->addFirewall('user', [
                'pattern' => '^' . static::USER_PAGE_PATH,
            ])
            ->addFirewall('default', [
                'pattern' => '^' . static::HOMEPAGE_PATH,
                'form' => [
                    'require_previous_session' => false,
                    'login_path' => static::HOMEPAGE_PATH . static::LOGIN_PATH,
                    'check_path' => static::HOMEPAGE_PATH . '/login_check',
                    'authenticators' => [
                        static::SECURITY_DEFAULT_LOGIN_FORM_AUTHENTICATOR,
                    ],
                ],
                'logout' => [
                    'logout_path' => static::HOMEPAGE_PATH . '/logout',
                    'target_url' => static::HOMEPAGE_PATH,
                ],
                'users' => [
                    static::USER_NAME => [static::ROLE_USER, static::USER_ENCODED_PASSWORD],
                    static::TARGET_USER_NAME => [static::ROLE_USER, static::USER_ENCODED_PASSWORD],
                ],
            ] + $additionalFirewallOptions)
            ->addAccessRules([['^' . static::USER_PAGE_PATH, static::ROLE_USER]]);

        $this->tester->mockZedSecurityPlugin($securityConfiguration);
        $this->tester->mockSecurityDependencies();
        $this->tester->enableSecurityApplicationPlugin();

        $container = $this->tester->getContainer();
        $container->set(static::SECURITY_DEFAULT_LOGIN_FORM_AUTHENTICATOR, function () {
            return new DefaultAuthenticator();
        });

        $this->tester->addRoute('homepage', static::HOMEPAGE_PATH, function () use ($container) {
            $token = $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE)->getToken();
            $content = $token ? $token->getUser()->getUserIdentifier() : static::ACCESS_MODE_PUBLIC;

            return new Response($content);
        });

        $this->tester->addRoute('login', static::LOGIN_PATH, function (Request $request) use ($container) {
            $container->get(static::SERVICE_SESSION)->start();
            $securityLastError = $container->get(static::SERVICE_SECURITY_LAST_ERROR);

            return $securityLastError($request);
        });

        $this->tester->addRoute('user', static::USER_PAGE_PATH, function (Request $request) use ($container) {
            $token = $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE)->getToken();
            $content = $token ? $token->getUser()->getUserIdentifier() : static::ACCESS_MODE_PUBLIC;

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::IS_AUTHENTICATED_FULLY)) {
                $content .= static::AUTHENTICATED;
            }

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::ROLE_USER)) {
                $content .= static::USER;
            }

            return new Response($content);
        });
    }

    protected function loginWithSwitchUser(): AbstractBrowser
    {
        $this->addFormAuthentication([
            'switch_user' => [
                'parameter' => static::PARAMETER_SWITCH_USER,
                'role' => static::ROLE_USER,
            ],
        ]);
        $httpKernelBrowser = $this->tester->getHttpKernelBrowser();
        $this->startSessionWithCookie($httpKernelBrowser);
        $httpKernelBrowser->request('post', static::HOMEPAGE_PATH . '/login_check', ['loginForm' => ['username' => static::USER_NAME, 'password' => static::USER_PASSWORD]]);

        return $httpKernelBrowser;
    }

    /**
     * @param array<string, string> $sessionAttributes
     */
    protected function startSessionWithCookie(AbstractBrowser $httpKernelBrowser, array $sessionAttributes = []): string
    {
        $httpKernelBrowser->request('get', static::HOMEPAGE_PATH);
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
                'pattern' => '^' . static::HOMEPAGE_PATH,
                'http' => true,
                'users' => [
                    static::USER_NAME => [static::ROLE_USER, static::USER_ENCODED_PASSWORD],
                ],
            ])
            ->addAccessRules([['^' . static::HOMEPAGE_PATH, static::ROLE_USER]]);

        $this->tester->mockZedSecurityPlugin($securityConfiguration);
        $this->tester->mockSecurityDependencies();
        $this->tester->enableSecurityApplicationPlugin();

        $this->tester->addRoute('homepage', static::HOMEPAGE_PATH, function () {
            $container = $this->tester->getContainer();
            if (!$container->has(static::SERVICE_SECURITY_TOKEN_STORAGE)) {
                return new Response(static::ACCESS_MODE_PUBLIC);
            }

            $token = $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE)->getToken();
            $content = $token->getUser()->getUserIdentifier();

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::IS_AUTHENTICATED_FULLY)) {
                $content .= static::AUTHENTICATED;
            }

            if ($container->get(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER)->isGranted(static::ROLE_USER)) {
                $content .= static::USER;
            }

            return new Response($content);
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
