<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security\Plugin\Application;

use LogicException;
use Psr\Log\LoggerInterface;
use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\ApplicationExtension\Dependency\Plugin\ApplicationPluginInterface;
use Spryker\Shared\ApplicationExtension\Dependency\Plugin\BootableApplicationPluginInterface;
use Spryker\Shared\Security\EventListener\RedirectLogoutListener;
use Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface;
use Spryker\Yves\Kernel\AbstractPlugin;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher;
use Symfony\Component\Routing\Loader\ClosureLoader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Router;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolver;
use Symfony\Component\Security\Core\Authentication\Provider\AnonymousAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Role\RoleHierarchy;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Validator\Constraints\UserPasswordValidator;
use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Guard\Firewall\GuardAuthenticationListener;
use Symfony\Component\Security\Guard\GuardAuthenticatorHandler;
use Symfony\Component\Security\Guard\Provider\GuardAuthenticationProvider;
use Symfony\Component\Security\Http\AccessMap;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\EntryPoint\BasicAuthenticationEntryPoint;
use Symfony\Component\Security\Http\EntryPoint\FormAuthenticationEntryPoint;
use Symfony\Component\Security\Http\EntryPoint\RetryAuthenticationEntryPoint;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\EventListener\RememberMeLogoutListener;
use Symfony\Component\Security\Http\EventListener\SessionLogoutListener;
use Symfony\Component\Security\Http\Firewall;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\Firewall\AccessListener;
use Symfony\Component\Security\Http\Firewall\AnonymousAuthenticationListener;
use Symfony\Component\Security\Http\Firewall\BasicAuthenticationListener;
use Symfony\Component\Security\Http\Firewall\ChannelListener;
use Symfony\Component\Security\Http\Firewall\ContextListener;
use Symfony\Component\Security\Http\Firewall\ExceptionListener;
use Symfony\Component\Security\Http\Firewall\LogoutListener;
use Symfony\Component\Security\Http\Firewall\SwitchUserListener;
use Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener;
use Symfony\Component\Security\Http\FirewallMap;
use Symfony\Component\Security\Http\FirewallMapInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Logout\DefaultLogoutSuccessHandler;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;
use Symfony\Component\Security\Http\Logout\SessionLogoutHandler;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

/**
 * @method \Spryker\Yves\Security\SecurityFactory getFactory()
 * @method \Spryker\Yves\Security\SecurityConfig getConfig()()
 */
class SecurityApplicationPlugin extends AbstractPlugin implements ApplicationPluginInterface, BootableApplicationPluginInterface
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
    protected const SERVICE_SECURITY_TOKEN_STORAGE = 'security.token_storage';

    /**
     * @var string
     */
    protected const SERVICE_USER = 'user';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_MANAGER = 'security.authentication_manager';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ACCESS_MANAGER = 'security.access_manager';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_PROVIDERS = 'security.authentication_providers';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ENCODER_FACTORY = 'security.encoder_factory';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_USER_CHECKER = 'security.user_checker';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_VOTERS = 'security.voters';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_TRUST_RESOLVER = 'security.trust_resolver';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_HTTP_UTILS = 'security.http_utils';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_LAST_ERROR = 'security.last_error';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ACCESS_MAP = 'security.access_map';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_UTILS = 'security.authentication_utils';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_CHANNEL_LISTENER = 'security.channel_listener';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ACCESS_LISTENER = 'security.access_listener';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_USER_PROVIDER_INMEMORY_PROTO = 'security.user_provider.inmemory._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_CONTEXT_LISTENER_PROTO = 'security.context_listener._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_EXCEPTION_LISTENER_PROTO = 'security.exception_listener._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_SUCCESS_HANDLER_PROTO = 'security.authentication.success_handler._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_FAILURE_HANDLER_PROTO = 'security.authentication.failure_handler._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LOGOUT_HANDLER_PROTO = 'security.authentication.logout_handler._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_GUARD_PROTO = 'security.authentication_listener.guard._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_GUARD_HANDLER = 'security.authentication.guard_handler';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_FORM_PROTO = 'security.authentication_listener.form._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_HTTP_PROTO = 'security.authentication_listener.http._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_ANONYMOUS_PROTO = 'security.authentication_listener.anonymous._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_LOGOUT_PROTO = 'security.authentication_listener.logout._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_SWITCH_USER_PROTO = 'security.authentication_listener.switch_user._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_LISTENER_CUSTOMER_SESSION_VALIDATOR_PROTO = 'security.authentication_listener.customer_session_validator._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ENTRY_POINT_FORM_PROTO = 'security.entry_point.form._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ENTRY_POINT_HTTP_PROTO = 'security.entry_point.http._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ENTRY_POINT_GUARD_PROTO = 'security.entry_point.guard._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_PROVIDER_DAO_PROTO = 'security.authentication_provider.dao._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_PROVIDER_GUARD_PROTO = 'security.authentication_provider.guard._proto';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_AUTHENTICATION_PROVIDER_ANONYMOUS_PROTO = 'security.authentication_provider.anonymous._proto';

    /**
     * @var string
     */
    protected const SERVICE_LOGGER = 'logger';

    /**
     * @uses \Spryker\Yves\Form\Plugin\Application\FormApplicationPlugin::SERVICE_FORM_CSRF_PROVIDER
     *
     * @var string
     */
    protected const SERVICE_FORM_CSRF_PROVIDER = 'form.csrf_provider';

    /**
     * @uses \Spryker\Yves\Http\Plugin\Application\HttpApplicationPlugin::SERVICE_REQUEST_STACK
     *
     * @var string
     */
    protected const SERVICE_REQUEST_STACK = 'request_stack';

    /**
     * @uses \Spryker\Yves\Router\Plugin\Application\RouterApplicationPlugin::SERVICE_ROUTER
     *
     * @var string
     */
    protected const SERVICE_ROUTER = 'routers';

    /**
     * @uses \Spryker\Yves\Http\Plugin\Application\HttpApplicationPlugin::SERVICE_KERNEL
     *
     * @var string
     */
    protected const SERVICE_KERNEL = 'kernel';

    /**
     * @uses \Spryker\Yves\EventDispatcher\Plugin\Application\EventDispatcherApplicationPlugin::SERVICE_DISPATCHER
     *
     * @var string
     */
    protected const SERVICE_DISPATCHER = 'dispatcher';

    /**
     * @uses \Spryker\Yves\Validator\Plugin\Application\ValidatorApplicationPlugin::SERVICE_VALIDATOR
     *
     * @var string
     */
    protected const SERVICE_VALIDATOR = 'validator';

    /**
     * @var list<string>
     */
    protected const DEFAULT_AUTHENTICATION_LISTENER_FACTORY_TYPES = [
        'logout',
        'pre_auth',
        'guard',
        'form',
        'http',
        'remember_me',
        'anonymous',
        'customer_session_validator',
    ];

    /**
     * @var array<array<string>>
     */
    protected array $securityRoutes = [];

    /**
     * @var \Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface|null
     */
    protected $securityConfiguration;

    /**
     * @var list<string>
     */
    protected array $authenticationListenerFactoryTypes = [];

    /**
     * {@inheritDoc}
     * - Executes the stack of {@link \Spryker\Shared\SecurityExtension\Dependency\Plugin\SecurityPluginInterface} plugins.
     * - Executes the stack of {@link \Spryker\Shared\SecurityExtension\Dependency\Plugin\SecurityAuthenticationListenerFactoryTypeExpanderPluginInterface} plugins.
     *
     * @api
     *
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    public function provide(ContainerInterface $container): ContainerInterface
    {
        $container = $this->addAuthorizationChecker($container);
        $container = $this->addTokenStorage($container);
        $container = $this->addUser($container);
        $container = $this->addAuthenticationManager($container);
        $container = $this->addEncoder($container);
        $container = $this->addUserChecker($container);
        $container = $this->addAccessManager($container);
        $container = $this->addVoters($container);
        $container = $this->addFirewall($container);
        $container = $this->addChannelListener($container);
        $container = $this->addAuthenticationListenerFactories($container);
        $container = $this->addAccessListener($container);
        $container = $this->addAccessMap($container);
        $container = $this->addTrustResolver($container);
        $container = $this->addUtils($container);
        $container = $this->addLastError($container);
        $container = $this->addUserProviderPrototypes($container);
        $container = $this->addListenerPrototypes($container);
        $container = $this->addAuthenticationHandlerPrototypes($container);
        $container = $this->addAuthenticationListenerPrototypes($container);
        $container = $this->addEntryPointPrototypes($container);
        $container = $this->addAuthenticationProviderPrototypes($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface
     */
    protected function getSecurityConfiguration(ContainerInterface $container): SecurityConfigurationInterface
    {
        if ($this->securityConfiguration === null) {
            $this->securityConfiguration = $this->getSecurityConfigurationFromPlugins($container);
        }

        return $this->securityConfiguration;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface
     */
    protected function getSecurityConfigurationFromPlugins(ContainerInterface $container): SecurityConfigurationInterface
    {
        $securityConfiguration = $this->getFactory()->createSecurityConfiguration();
        foreach ($this->getFactory()->getSecurityPlugins() as $securityPlugin) {
            $securityConfiguration = $securityPlugin->extend($securityConfiguration, $container);
        }

        return $securityConfiguration->getConfiguration();
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthorizationChecker(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHORIZATION_CHECKER, function (ContainerInterface $container) {
            return new AuthorizationChecker(
                $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                $container->get(static::SERVICE_SECURITY_AUTHENTICATION_MANAGER),
                $container->get(static::SERVICE_SECURITY_ACCESS_MANAGER),
                false, // Shim for Symfony Security Core 5.2.8 - 5.3.*, to be removed when Symfony Security Core dependency becomes 5.4+
            );
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addTokenStorage(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_TOKEN_STORAGE, function () {
            return new TokenStorage();
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addUser(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_USER, $container->factory(function (ContainerInterface $container) {
            $token = $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE)->getToken();
            if ($token === null) {
                return null;
            }

            $user = $token->getUser();

            if (!is_object($user)) {
                return null;
            }

            return $user;
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationManager(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_MANAGER, function (ContainerInterface $container) {
            $manager = new AuthenticationProviderManager($container->get(static::SERVICE_SECURITY_AUTHENTICATION_PROVIDERS));
            $manager->setEventDispatcher($container->get(static::SERVICE_DISPATCHER));

            return $manager;
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addEncoder(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ENCODER_FACTORY, function () {
            return new EncoderFactory([
                UserInterface::class => $this->getFactory()->createPasswordEncoder(),
            ]);
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addUserChecker(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_USER_CHECKER, function () {
            return new UserChecker();
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAccessManager(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ACCESS_MANAGER, function (ContainerInterface $container) {
            return new AccessDecisionManager($container->get(static::SERVICE_SECURITY_VOTERS));
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addVoters(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_VOTERS, function (ContainerInterface $container) {
            $securityConfiguration = $this->getSecurityConfiguration($container);

            return [
                new RoleHierarchyVoter(new RoleHierarchy($securityConfiguration->getRoleHierarchies())),
                new AuthenticatedVoter($container->get(static::SERVICE_SECURITY_TRUST_RESOLVER)),
            ];
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addFirewall(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_FIREWALL, function (ContainerInterface $container) {
            $this->addUserPasswordValidator($container);

            return new Firewall($this->getFirewallMap($container), $container->get(static::SERVICE_DISPATCHER));
        });

        return $container;
    }

    /**
     * @deprecated This method exists only for BC reasons. To add the
     *     `\Symfony\Component\Security\Core\Validator\Constraints\UserPasswordValidator` use the
     *     `UserPasswordValidatorConstraintPlugin`.
     *
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return void
     */
    protected function addUserPasswordValidator(ContainerInterface $container): void
    {
        if ($container->has(static::SERVICE_VALIDATOR) && $container->has('validator.validator_service_ids')) {
            $container->set('security.validator.user_password_validator', function (ContainerInterface $container) {
                return new UserPasswordValidator($container->get(static::SERVICE_SECURITY_TOKEN_STORAGE), $container->get(static::SERVICE_SECURITY_ENCODER_FACTORY));
            });

            $container->set('validator.validator_service_ids', array_merge(
                $container->get('validator.validator_service_ids'),
                ['security.validator.user_password' => 'security.validator.user_password_validator'],
            ));
        }
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @throws \LogicException
     *
     * @return \Symfony\Component\Security\Http\FirewallMapInterface
     */
    protected function getFirewallMap(ContainerInterface $container): FirewallMapInterface
    {
        $providers = [];
        $configs = [];

        foreach ($this->getSecurityConfiguration($container)->getFirewalls() as $firewallName => $firewallConfiguration) {
            $entryPoint = null;
            $pattern = $firewallConfiguration['pattern'] ?? null;
            $users = $firewallConfiguration['users'] ?? [];
            $security = (bool)($firewallConfiguration['security'] ?? true);
            $stateless = (bool)($firewallConfiguration['stateless'] ?? false);
            $context = $firewallConfiguration['context'] ?? $firewallName;
            $hosts = $firewallConfiguration['hosts'] ?? null;
            $methods = $firewallConfiguration['methods'] ?? null;
            unset($firewallConfiguration['pattern'], $firewallConfiguration['users'], $firewallConfiguration['security'], $firewallConfiguration['stateless'], $firewallConfiguration['context'], $firewallConfiguration['methods'], $firewallConfiguration['hosts']);
            $protected = $security === false ? false : count($firewallConfiguration);
            $listeners = [static::SERVICE_SECURITY_CHANNEL_LISTENER];

            if (is_string($users)) {
                $users = function () use ($container, $users) {
                    return $container->get($users);
                };
            }

            if ($protected) {
                if (!$container->has('security.user_provider.' . $firewallName)) {
                    $container->set('security.user_provider.' . $firewallName, is_array($users) ? $container->get(static::SERVICE_SECURITY_USER_PROVIDER_INMEMORY_PROTO)($users) : $users);
                }

                if (!$container->has('security.context_listener.' . $context)) {
                    $container->set('security.context_listener.' . $context, $container->get(static::SERVICE_SECURITY_CONTEXT_LISTENER_PROTO)($firewallName, [$container->get('security.user_provider.' . $firewallName)]));
                }

                if ($stateless === false) {
                    $listeners[] = 'security.context_listener.' . $context;
                }

                $factories = [];
                foreach ($this->getAuthenticationListenerFactoryTypes() as $authenticationListenerFactoryType) {
                    $factories[$authenticationListenerFactoryType] = [];
                }

                foreach ($firewallConfiguration as $type => $options) {
                    if ($type === 'switch_user') {
                        continue;
                    }
                    // normalize options
                    if (!is_array($options)) {
                        if (!$options) {
                            continue;
                        }
                        $options = [];
                    }
                    if (!$container->has('security.authentication_listener.factory.' . $type)) {
                        throw new LogicException(sprintf('The "%s" authentication entry is not registered.', $type));
                    }
                    $options['stateless'] = $stateless;
                    [$providerId, $listenerId, $entryPointId, $authenticationListenerFactoryType] = $container->get('security.authentication_listener.factory.' . $type)($firewallName, $options);
                    if ($entryPointId !== null) {
                        $entryPoint = $entryPointId;
                    }
                    $factories[$authenticationListenerFactoryType][] = $listenerId;
                    $providers[] = $providerId;
                }

                foreach ($this->getAuthenticationListenerFactoryTypes() as $authenticationListenerFactoryType) {
                    foreach ($factories[$authenticationListenerFactoryType] as $listener) {
                        $listeners[] = $listener;
                    }
                }

                $listeners[] = static::SERVICE_SECURITY_ACCESS_LISTENER;
                if (isset($firewallConfiguration['switch_user'])) {
                    $switchUserConfiguration = (array)$firewallConfiguration['switch_user'];
                    $switchUserConfiguration['stateless'] = $stateless;
                    $container->set('security.switch_user.' . $firewallName, $container->get(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_SWITCH_USER_PROTO)($firewallName, $switchUserConfiguration));
                    $listeners[] = 'security.switch_user.' . $firewallName;
                }

                $container = $this->setFirewallExceptionListener($firewallName, $entryPoint, $container);
            }
            $configs[$firewallName] = [
                'pattern' => $pattern,
                'listeners' => $listeners,
                'protected' => $protected,
                'methods' => $methods,
                'hosts' => $hosts,
            ];
        }

        $securityAuthenticationProviders = array_map(function ($provider) use ($container) {
            return $container->get($provider);
        }, array_unique($providers));

        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_PROVIDERS, $securityAuthenticationProviders);

        return $this->buildFirewallMap($container, $configs);
    }

    /**
     * @param string $firewallName
     * @param string|null $entryPoint
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function setFirewallExceptionListener(string $firewallName, ?string $entryPoint, ContainerInterface $container): ContainerInterface
    {
        if (!$container->has('security.exception_listener.' . $firewallName)) {
            if ($entryPoint === null) {
                $entryPoint = 'security.entry_point.' . $firewallName . '.form';
                $container->set($entryPoint, $container->get(static::SERVICE_SECURITY_ENTRY_POINT_FORM_PROTO)($firewallName, []));
            }
            $accessDeniedHandler = null;
            if ($container->has('security.access_denied_handler.' . $firewallName)) {
                $accessDeniedHandler = $container->get('security.access_denied_handler.' . $firewallName);
            }

            $securityConfiguration = $this->getSecurityConfiguration($container);
            if (isset($securityConfiguration->getAccessDeniedHandlers()[$firewallName])) {
                $accessDeniedHandler = call_user_func($securityConfiguration->getAccessDeniedHandlers()[$firewallName], $container);
            }

            $container->set('security.exception_listener.' . $firewallName, $container->get(static::SERVICE_SECURITY_EXCEPTION_LISTENER_PROTO)($entryPoint, $firewallName, $accessDeniedHandler));
        }

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param array $configs
     *
     * @return \Symfony\Component\Security\Http\FirewallMapInterface
     */
    protected function buildFirewallMap(ContainerInterface $container, array $configs): FirewallMapInterface
    {
        $firewallMap = new FirewallMap();
        foreach ($configs as $firewallName => $config) {
            $requestMatcher = $config['pattern'];
            if (is_string($config['pattern'])) {
                $requestMatcher = new RequestMatcher($config['pattern'], $config['hosts'], $config['methods']);
            }

            $firewallMap->add(
                $requestMatcher,
                $this->mapListeners($container, $config['listeners'], $firewallName),
                $config['protected'] ? $container->get('security.exception_listener.' . $firewallName) : null,
            );
        }

        return $firewallMap;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param array $listeners
     * @param string $firewallName
     *
     * @return array
     */
    protected function mapListeners(ContainerInterface $container, array $listeners, string $firewallName): array
    {
        return array_map(function ($listenerId) use ($container, $firewallName) {
            $listener = $container->get($listenerId);
            if ($container->has('security.remember_me.service.' . $firewallName)) {
                if ($listener instanceof AbstractAuthenticationListener || $listener instanceof GuardAuthenticationListener) {
                    $listener->setRememberMeServices($container->get('security.remember_me.service.' . $firewallName));
                }
                if ($listener instanceof LogoutListener && !class_exists(LogoutEvent::class)) {
                    $listener->addHandler($container->get('security.remember_me.service.' . $firewallName));
                }

                if (class_exists(LogoutEvent::class)) {
                    $this->getDispatcher($container)->addSubscriber(new RememberMeLogoutListener($container->get('security.remember_me.service.' . $firewallName)));
                }
            }

            return $listener;
        }, $listeners);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addChannelListener(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_CHANNEL_LISTENER, function (ContainerInterface $container) {
            return new ChannelListener(
                $container->get(static::SERVICE_SECURITY_ACCESS_MAP),
                new RetryAuthenticationEntryPoint(
                    $this->getConfig()->getHttpPort(),
                    $this->getConfig()->getHttpsPort(),
                ),
                $this->getLogger($container),
            );
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerFactories(ContainerInterface $container): ContainerInterface
    {
        foreach ($this->getAuthenticationListenerFactoryTypes() as $type) {
            $entryPoint = $this->getEntryPoint($type);

            $container->set('security.authentication_listener.factory.' . $type, $container->protect(function ($firewallName, $options) use ($type, $container, $entryPoint) {
                if ($entryPoint && !$container->has('security.entry_point.' . $firewallName . '.' . $entryPoint)) {
                    $container->set('security.entry_point.' . $firewallName . '.' . $entryPoint, $container->get('security.entry_point.' . $entryPoint . '._proto')($firewallName, $options));
                }
                if (!$container->has('security.authentication_listener.' . $firewallName . '.' . $type)) {
                    $container->set('security.authentication_listener.' . $firewallName . '.' . $type, $container->get('security.authentication_listener.' . $type . '._proto')($firewallName, $options));
                }
                $provider = $this->getProvider($type);

                if (!$container->has('security.authentication_provider.' . $firewallName . '.' . $provider)) {
                    $container->set('security.authentication_provider.' . $firewallName . '.' . $provider, $container->get('security.authentication_provider.' . $provider . '._proto')($firewallName, $options));
                }

                return [
                    'security.authentication_provider.' . $firewallName . '.' . $provider,
                    'security.authentication_listener.' . $firewallName . '.' . $type,
                    $entryPoint ? 'security.entry_point.' . $firewallName . '.' . $entryPoint : null,
                    $type,
                ];
            }));
        }

        return $container;
    }

    /**
     * @param string $type
     *
     * @return string|null
     */
    protected function getEntryPoint(string $type): ?string
    {
        if (in_array($type, ['http', 'form', 'guard'])) {
            return $type;
        }

        return null;
    }

    /**
     * @param string $type
     *
     * @return string|null
     */
    protected function getProvider(string $type): ?string
    {
        if (in_array($type, ['anonymous', 'guard'])) {
            return $type;
        }

        return 'dao';
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAccessListener(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ACCESS_LISTENER, function (ContainerInterface $container) {
            return new AccessListener(
                $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                $container->get(static::SERVICE_SECURITY_ACCESS_MANAGER),
                $container->get(static::SERVICE_SECURITY_ACCESS_MAP),
                $container->get(static::SERVICE_SECURITY_AUTHENTICATION_MANAGER),
            );
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAccessMap(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ACCESS_MAP, function (ContainerInterface $container) {
            $map = new AccessMap();
            $accessRules = $this->getSecurityConfiguration($container)->getAccessRules();
            foreach ($accessRules as $rule) {
                if (is_string($rule[0])) {
                    $rule[0] = new RequestMatcher($rule[0]);
                } elseif (is_array($rule[0])) {
                    $rule[0] += [
                        'path' => null,
                        'host' => null,
                        'methods' => null,
                        'ips' => null,
                        'attributes' => [],
                        'schemes' => null,
                    ];
                    $rule[0] = new RequestMatcher($rule[0]['path'], $rule[0]['host'], $rule[0]['methods'], $rule[0]['ips'], $rule[0]['attributes'], $rule[0]['schemes']);
                }
                $map->add($rule[0], (array)$rule[1], $rule[2] ?? null);
            }

            return $map;
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addTrustResolver(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_TRUST_RESOLVER, function () {
            if (method_exists(AuthenticationTrustResolver::class, '__construct')) {
                return new AuthenticationTrustResolver(AnonymousToken::class, RememberMeToken::class);
            }

            return new AuthenticationTrustResolver();
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addUtils(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_HTTP_UTILS, function (ContainerInterface $container) {
            $chainRouter = $container->get(static::SERVICE_ROUTER);

            return new HttpUtils($chainRouter, $chainRouter);
        });

        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_UTILS, function (ContainerInterface $container) {
            return new AuthenticationUtils($container->get(static::SERVICE_REQUEST_STACK));
        });

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addLastError(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_LAST_ERROR, $container->protect(function (Request $request) {
            if ($request->attributes->has(Security::AUTHENTICATION_ERROR)) {
                return $request->attributes->get(Security::AUTHENTICATION_ERROR)->getMessage();
            }

            if (!$request->hasSession()) {
                return null;
            }

            /** @var \Symfony\Component\HttpFoundation\Session\SessionInterface $session */
            $session = $request->getSession();

            if ($session->has(Security::AUTHENTICATION_ERROR)) {
                $message = $session->get(Security::AUTHENTICATION_ERROR)->getMessage();
                $session->remove(Security::AUTHENTICATION_ERROR);

                return $message;
            }
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addUserProviderPrototypes(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_USER_PROVIDER_INMEMORY_PROTO, $container->protect(function ($params) {
            return function () use ($params) {
                $users = [];

                /** @var string $name */
                foreach ($params as $name => $user) {
                    /** @var array<int, string> $roles */
                    $roles = (array)$user[0];

                    $users[$name] = ['roles' => $roles, 'password' => (string)$user[1]];
                }

                return new InMemoryUserProvider($users);
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addListenerPrototypes(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_CONTEXT_LISTENER_PROTO, $container->protect(function ($providerKey, $userProviders) use ($container) {
            return function () use ($container, $userProviders, $providerKey) {
                return new ContextListener(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $userProviders,
                    $providerKey,
                    $this->getLogger($container),
                    $container->get(static::SERVICE_DISPATCHER),
                );
            };
        }));

        $container->set(static::SERVICE_SECURITY_EXCEPTION_LISTENER_PROTO, $container->protect(function ($entryPoint, $name, $accessDeniedHandler = null) use ($container) {
            return function () use ($container, $entryPoint, $name, $accessDeniedHandler) {
                return new ExceptionListener(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $container->get(static::SERVICE_SECURITY_TRUST_RESOLVER),
                    $container->get(static::SERVICE_SECURITY_HTTP_UTILS),
                    $name,
                    $container->get($entryPoint),
                    null, // errorPage
                    $accessDeniedHandler,
                    $this->getLogger($container),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationHandlerPrototypes(ContainerInterface $container): ContainerInterface
    {
        $container = $this->addAuthenticationSuccessHandlerPrototype($container);
        $container = $this->addAuthenticationFailureHandlerPrototype($container);
        $container = $this->addAuthenticationLogoutHandlerPrototype($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationSuccessHandlerPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_SUCCESS_HANDLER_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($name, $options, $container) {
                $handler = new DefaultAuthenticationSuccessHandler(
                    $container->get(static::SERVICE_SECURITY_HTTP_UTILS),
                    $options,
                );
                $handler->setProviderKey($name);

                return $handler;
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationFailureHandlerPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_FAILURE_HANDLER_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($options, $container) {
                return new DefaultAuthenticationFailureHandler(
                    $container->get(static::SERVICE_KERNEL),
                    $container->get(static::SERVICE_SECURITY_HTTP_UTILS),
                    $options,
                    $this->getLogger($container),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationLogoutHandlerPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LOGOUT_HANDLER_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($options, $container) {
                return new DefaultLogoutSuccessHandler(
                    $container->get(static::SERVICE_SECURITY_HTTP_UTILS),
                    $options['target_url'] ?? '/',
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerPrototypes(ContainerInterface $container): ContainerInterface
    {
        $container = $this->addAuthenticationListenerGuardPrototype($container);
        $container = $this->addAuthenticationListenerFormPrototype($container);
        $container = $this->addAuthenticationListenerHttpPrototype($container);
        $container = $this->addAuthenticationListenerAnonymousPrototype($container);
        $container = $this->addAuthenticationListenerSwitchUserPrototype($container);
        $container = $this->addAuthenticationListenerLogoutPrototype($container);
        $container = $this->addCustomerSessionValidatorListenerPrototype($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerGuardPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_GUARD_PROTO, $container->protect(function ($providerKey, $options) use ($container) {
            return function () use ($container, $providerKey, $options) {
                if (!$container->has(static::SERVICE_SECURITY_AUTHENTICATION_GUARD_HANDLER)) {
                    $container->set(static::SERVICE_SECURITY_AUTHENTICATION_GUARD_HANDLER, new GuardAuthenticatorHandler($container->get(static::SERVICE_SECURITY_TOKEN_STORAGE), $container->get(static::SERVICE_DISPATCHER)));
                }
                $authenticators = [];
                foreach ($options['authenticators'] as $authenticatorId) {
                    $authenticators[] = $container->get($authenticatorId);
                }

                return new GuardAuthenticationListener(
                    $container->get(static::SERVICE_SECURITY_AUTHENTICATION_GUARD_HANDLER),
                    $container->get(static::SERVICE_SECURITY_AUTHENTICATION_MANAGER),
                    $providerKey,
                    $authenticators,
                    $this->getLogger($container),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerFormPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_FORM_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($container, $name, $options) {
                $tmp = $options['check_path'] ?? '/login_check';
                $this->addSecurityRoute('match', $tmp);

                $class = $options['listener_class'] ?? UsernamePasswordFormAuthenticationListener::class;

                return new $class(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $container->get(static::SERVICE_SECURITY_AUTHENTICATION_MANAGER),
                    $this->getSessionStrategy($container, $name),
                    $container->get(static::SERVICE_SECURITY_HTTP_UTILS),
                    $name,
                    $this->getAuthenticationSuccessHandler($container, $name, $options),
                    $this->getAuthenticationFailureHandler($container, $name, $options),
                    $options,
                    $this->getLogger($container),
                    $container->get(static::SERVICE_DISPATCHER),
                    $this->getCsrfTokenManager($container, $options),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addCustomerSessionValidatorListenerPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_CUSTOMER_SESSION_VALIDATOR_PROTO, $container->protect(function ($firewallName, $options) {
            return function () {
                return function () {
                };
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param string $name
     *
     * @return \Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface
     */
    protected function getSessionStrategy(ContainerInterface $container, string $name): SessionAuthenticationStrategyInterface
    {
        return $container->has('security.session_strategy.' . $name) ? $container->get('security.session_strategy.' . $name) : $this->getFactory()->createSessionStrategy();
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Psr\Log\LoggerInterface|null
     */
    protected function getLogger(ContainerInterface $container): ?LoggerInterface
    {
        return $container->has(static::SERVICE_LOGGER) ? $container->get(static::SERVICE_LOGGER) : null;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param string $firewallName
     * @param array<string, mixed> $options
     *
     * @return \Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface
     */
    protected function getAuthenticationSuccessHandler(
        ContainerInterface $container,
        string $firewallName,
        array $options
    ): AuthenticationSuccessHandlerInterface {
        $securityConfiguration = $this->getSecurityConfiguration($container);
        if (isset($securityConfiguration->getAuthenticationSuccessHandlers()[$firewallName])) {
            return call_user_func($securityConfiguration->getAuthenticationSuccessHandlers()[$firewallName], $container, $options);
        }

        if (!$container->has('security.authentication.success_handler.' . $firewallName)) {
            $container->set('security.authentication.success_handler.' . $firewallName, $container->get(static::SERVICE_SECURITY_AUTHENTICATION_SUCCESS_HANDLER_PROTO)($firewallName, $options));
        }

        return $container->get('security.authentication.success_handler.' . $firewallName);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param string $firewallName
     * @param array<string, mixed> $options
     *
     * @return \Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface
     */
    protected function getAuthenticationFailureHandler(
        ContainerInterface $container,
        string $firewallName,
        array $options
    ): AuthenticationFailureHandlerInterface {
        $securityConfiguration = $this->getSecurityConfiguration($container);
        if (isset($securityConfiguration->getAuthenticationFailureHandlers()[$firewallName])) {
            return call_user_func($securityConfiguration->getAuthenticationFailureHandlers()[$firewallName], $container, $options);
        }

        if (!$container->has('security.authentication.failure_handler.' . $firewallName)) {
            $container->set('security.authentication.failure_handler.' . $firewallName, $container->get(static::SERVICE_SECURITY_AUTHENTICATION_FAILURE_HANDLER_PROTO)($firewallName, $options));
        }

        return $container->get('security.authentication.failure_handler.' . $firewallName);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerHttpPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_HTTP_PROTO, $container->protect(function ($providerKey, $options) use ($container) {
            return function () use ($container, $providerKey) {
                return new BasicAuthenticationListener(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $container->get(static::SERVICE_SECURITY_AUTHENTICATION_MANAGER),
                    $providerKey,
                    $container->get('security.entry_point.' . $providerKey . '.http'),
                    $this->getLogger($container),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerAnonymousPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_ANONYMOUS_PROTO, $container->protect(function ($providerKey, $options) use ($container) {
            return function () use ($container, $providerKey) {
                return new AnonymousAuthenticationListener(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $providerKey,
                    $this->getLogger($container),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerLogoutPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_LOGOUT_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($container, $name, $options) {
                $tmp = $options['logout_path'] ?? '/logout';
                $this->addSecurityRoute('get', $tmp);

                $logoutEventClassExist = class_exists(LogoutEvent::class);
                /** @var \Symfony\Contracts\EventDispatcher\EventDispatcherInterface|\Symfony\Component\EventDispatcher\EventDispatcherInterface $eventDispatcher */
                $eventDispatcher = $this->getDispatcher($container);
                if ($logoutEventClassExist) {
                    $httpUtils = $container->get(static::SERVICE_SECURITY_HTTP_UTILS);
                    $requestMatcher = $this->createRequestMatcher($container, $name);

                    $this->getDispatcher($container)->addSubscriber(new RedirectLogoutListener(
                        $httpUtils,
                        $requestMatcher,
                        $options['target_url'] ?? '/',
                        $options['priority'] ?? 64,
                    ));
                    $this->getDispatcher($container)->addSubscriber(new SessionLogoutListener());
                }

                $listener = new LogoutListener(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $container->get(static::SERVICE_SECURITY_HTTP_UTILS),
                    ($logoutEventClassExist) ? $eventDispatcher : $this->getLogoutHandler($container, $name, $options),
                    $options,
                    $this->getCsrfTokenManager($container, $options),
                );

                if (!$logoutEventClassExist) {
                    $listener = $this->addSessionLogoutHandler($listener, $options);
                }

                return $listener;
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param string $firewallName
     * @param array<string, mixed> $options
     *
     * @return \Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface
     */
    protected function getLogoutHandler(ContainerInterface $container, string $firewallName, array $options): LogoutSuccessHandlerInterface
    {
        $securityConfiguration = $this->getSecurityConfiguration($container);
        if (isset($securityConfiguration->getLogoutHandlers()[$firewallName])) {
            return call_user_func($securityConfiguration->getLogoutHandlers()[$firewallName], $container, $options);
        }

        if (!$container->has('security.authentication.logout_handler.' . $firewallName)) {
            $container->set('security.authentication.logout_handler.' . $firewallName, $container->get(static::SERVICE_SECURITY_AUTHENTICATION_LOGOUT_HANDLER_PROTO)($firewallName, $options));
        }

        return $container->get('security.authentication.logout_handler.' . $firewallName);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param array<string, mixed> $options
     *
     * @return \Symfony\Component\Security\Csrf\CsrfTokenManager|null
     */
    protected function getCsrfTokenManager(ContainerInterface $container, array $options): ?CsrfTokenManager
    {
        return !empty($options['with_csrf']) && $container->has(static::SERVICE_FORM_CSRF_PROVIDER) ? $container->get(static::SERVICE_FORM_CSRF_PROVIDER) : null;
    }

    /**
     * @param \Symfony\Component\Security\Http\Firewall\LogoutListener $listener
     * @param array<string, mixed> $options
     *
     * @return \Symfony\Component\Security\Http\Firewall\LogoutListener
     */
    protected function addSessionLogoutHandler(LogoutListener $listener, array $options): LogoutListener
    {
        $invalidateSession = $options['invalidate_session'] ?? true;

        if ($invalidateSession === true && $options['stateless'] === false) {
            $listener->addHandler(new SessionLogoutHandler());
        }

        return $listener;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationListenerSwitchUserPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_LISTENER_SWITCH_USER_PROTO, $container->protect(function ($firewallName, $options) use ($container) {
            return function () use ($container, $firewallName, $options) {
                return new SwitchUserListener(
                    $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE),
                    $container->get('security.user_provider.' . $firewallName),
                    $container->get(static::SERVICE_SECURITY_USER_CHECKER),
                    $firewallName,
                    $container->get(static::SERVICE_SECURITY_ACCESS_MANAGER),
                    $this->getLogger($container),
                    $options['parameter'] ?? '_switch_user',
                    $options['role'] ?? 'ROLE_ALLOWED_TO_SWITCH',
                    $container->get(static::SERVICE_DISPATCHER),
                    $options['stateless'] ?? true,
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addEntryPointPrototypes(ContainerInterface $container): ContainerInterface
    {
        $container = $this->addEntryPointFormPrototype($container);
        $container = $this->addEntryPointHttpPrototype($container);
        $container = $this->addEntryPointGuardPrototype($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addEntryPointFormPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ENTRY_POINT_FORM_PROTO, $container->protect(function ($name, array $options) use ($container) {
            return function () use ($container, $options) {
                $loginPath = $options['login_path'] ?? '/login';
                $useForward = $options['use_forward'] ?? false;

                return new FormAuthenticationEntryPoint($container->get(static::SERVICE_KERNEL), $container->get(static::SERVICE_SECURITY_HTTP_UTILS), $loginPath, $useForward);
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addEntryPointHttpPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ENTRY_POINT_HTTP_PROTO, $container->protect(function ($name, array $options) {
            return function () use ($options) {
                return new BasicAuthenticationEntryPoint($options['real_name'] ?? 'Secured');
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addEntryPointGuardPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ENTRY_POINT_GUARD_PROTO, $container->protect(function ($name, array $options) use ($container) {
            if (isset($options['entry_point'])) {
                return $container->get($options['entry_point']);
            }

            $authenticatorIds = $options['authenticators'];

            if (count($authenticatorIds) === 1) {
                return $container->get(reset($authenticatorIds));
            }

            throw new LogicException(sprintf(
                'Because you have multiple guard configurators, you need to set the "guard.entry_point" key to one of your configurators (%s)',
                implode(', ', $authenticatorIds),
            ));
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationProviderPrototypes(ContainerInterface $container): ContainerInterface
    {
        $container = $this->addAuthenticationProviderDaoPrototype($container);
        $container = $this->addAuthenticationProviderGuardPrototype($container);
        $container = $this->addAuthenticationProviderAnonymousPrototype($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationProviderDaoPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_PROVIDER_DAO_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($container, $name) {
                return new DaoAuthenticationProvider(
                    $container->get('security.user_provider.' . $name),
                    $container->get(static::SERVICE_SECURITY_USER_CHECKER),
                    $name,
                    $container->get(static::SERVICE_SECURITY_ENCODER_FACTORY),
                    $this->getConfig()->hideUserNotFoundException(),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationProviderGuardPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_PROVIDER_GUARD_PROTO, $container->protect(function ($name, $options) use ($container) {
            return function () use ($container, $name, $options) {
                $authenticators = [];
                foreach ($options['authenticators'] as $authenticatorId) {
                    $authenticators[] = $container->get($authenticatorId);
                }

                return new GuardAuthenticationProvider(
                    $authenticators,
                    $container->get('security.user_provider.' . $name),
                    $name,
                    $container->get(static::SERVICE_SECURITY_USER_CHECKER),
                );
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    protected function addAuthenticationProviderAnonymousPrototype(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_AUTHENTICATION_PROVIDER_ANONYMOUS_PROTO, $container->protect(function ($name, $options) {
            return function () use ($name) {
                return new AnonymousAuthenticationProvider($name);
            };
        }));

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Spryker\Service\Container\ContainerInterface
     */
    public function boot(ContainerInterface $container): ContainerInterface
    {
        $this->addSubscriber($container);
        $this->addRouter($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return void
     */
    protected function addSubscriber(ContainerInterface $container): void
    {
        $dispatcher = $this->getDispatcher($container);
        $dispatcher->addSubscriber($container->get(static::SERVICE_SECURITY_FIREWALL));

        foreach ($this->getSecurityConfiguration($container)->getEventSubscribers() as $eventSubscriber) {
            $dispatcher->addSubscriber(call_user_func($eventSubscriber, $container));
        }
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\EventDispatcher\EventDispatcherInterface
     */
    protected function getDispatcher(ContainerInterface $container): EventDispatcherInterface
    {
        return $container->get(static::SERVICE_DISPATCHER);
    }

    /**
     * @param string $method
     * @param string $routeNameOrUrl
     * @param string|null $routeName
     *
     * @return void
     */
    protected function addSecurityRoute(string $method, string $routeNameOrUrl, ?string $routeName = null): void
    {
        $url = $this->buildUrl($routeNameOrUrl);
        $routeName = $this->buildRouteName($routeNameOrUrl, $routeName);

        $this->securityRoutes[] = [$method, $url, $routeName];
    }

    /**
     * @param string $routeNameOrUrl
     *
     * @return string
     */
    protected function buildUrl(string $routeNameOrUrl): string
    {
        if ($routeNameOrUrl[0] === '/') {
            return $routeNameOrUrl;
        }

        return '/' . str_replace('_', '/', ltrim($routeNameOrUrl, '/'));
    }

    /**
     * @param string $routeNameOrUrl
     * @param string|null $routeName
     *
     * @return string
     */
    protected function buildRouteName(string $routeNameOrUrl, ?string $routeName = null): string
    {
        if ($routeName) {
            return $routeName;
        }

        return str_replace('/', '_', ltrim($routeNameOrUrl, '/'));
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return void
     */
    protected function addRouter(ContainerInterface $container): void
    {
        $loader = new ClosureLoader();
        $securityRoutes = $this->securityRoutes;

        $resource = function () use ($securityRoutes) {
            $routeCollection = new RouteCollection();
            foreach ($securityRoutes as $route) {
                [$method, $url, $name] = $route;

                $route = new Route($url);

                $controller = function (Request $request): void {
                    throw new LogicException('None of the configured firewalls matched. Please check your firewall configuration.');
                };

                $route->setDefault('_controller', $controller);

                $routeCollection->add($name, $route, 0);
            }

            return $routeCollection;
        };

        $router = new Router($loader, $resource, []);
        $container->get(static::SERVICE_ROUTER)->add($router, 1);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     * @param string $name
     *
     * @return \Symfony\Component\HttpFoundation\RequestMatcher|mixed
     */
    protected function createRequestMatcher(ContainerInterface $container, string $name)
    {
        $config = $this->getSecurityConfiguration($container)->getFirewalls()[$name];
        $requestMatcher = $config['pattern'];
        if (is_string($config['pattern'])) {
            $requestMatcher = new RequestMatcher(
                $config['pattern'],
                $config['hosts'] ?? null,
                $config['methods'] ?? null,
            );
        }

        return $requestMatcher;
    }

    /**
     * @return list<string>
     */
    protected function getAuthenticationListenerFactoryTypes(): array
    {
        if ($this->authenticationListenerFactoryTypes === []) {
            $this->initializeAuthenticationListenerFactoryTypes();
        }

        return $this->authenticationListenerFactoryTypes;
    }

    /**
     * @return void
     */
    protected function initializeAuthenticationListenerFactoryTypes(): void
    {
        $this->authenticationListenerFactoryTypes = static::DEFAULT_AUTHENTICATION_LISTENER_FACTORY_TYPES;

        foreach ($this->getFactory()->getSecurityAuthenticationListenerFactoryTypeExpanderPlugins() as $securityAuthenticationListenerFactoryTypeExpanderPlugin) {
            $this->authenticationListenerFactoryTypes = $securityAuthenticationListenerFactoryTypeExpanderPlugin->expand(
                $this->authenticationListenerFactoryTypes,
            );
        }
    }
}
