<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security;

use Spryker\Shared\Security\Configuration\SecurityConfiguration;
use Spryker\Yves\Kernel\AbstractFactory;
use Spryker\Yves\Security\AuthenticationListener\AuthenticationListener;
use Spryker\Yves\Security\AuthenticationListener\AuthenticationListenerInterface;
use Spryker\Yves\Security\Booter\SecurityApplicationBooter;
use Spryker\Yves\Security\Booter\SecurityApplicationBooterInterface;
use Spryker\Yves\Security\Configurator\SecurityConfigurator;
use Spryker\Yves\Security\Configurator\SecurityConfiguratorInterface;
use Spryker\Yves\Security\Loader\AuthenticatorManager\AuthenticatorManager;
use Spryker\Yves\Security\Loader\AuthenticatorManager\AuthenticatorManagerInterface;
use Spryker\Yves\Security\Loader\Services\AccessListenerServiceLoader;
use Spryker\Yves\Security\Loader\Services\AccessManagerServiceLoader;
use Spryker\Yves\Security\Loader\Services\AccessMapServiceLoader;
use Spryker\Yves\Security\Loader\Services\AuthenticationListenerFactoriesServiceLoader;
use Spryker\Yves\Security\Loader\Services\AuthenticationListenerPrototypesServiceLoader;
use Spryker\Yves\Security\Loader\Services\AuthenticationManagerServiceLoader;
use Spryker\Yves\Security\Loader\Services\AuthorizationCheckerServiceLoader;
use Spryker\Yves\Security\Loader\Services\ChannelListenerServiceLoader;
use Spryker\Yves\Security\Loader\Services\EncoderServiceLoader;
use Spryker\Yves\Security\Loader\Services\EntryPointPrototypesServiceLoader;
use Spryker\Yves\Security\Loader\Services\FirewallServiceLoader;
use Spryker\Yves\Security\Loader\Services\LastErrorServiceLoader;
use Spryker\Yves\Security\Loader\Services\ListenerPrototypeServiceLoader;
use Spryker\Yves\Security\Loader\Services\ServiceLoaderInterface;
use Spryker\Yves\Security\Loader\Services\TokenStorageServiceLoader;
use Spryker\Yves\Security\Loader\Services\TrustResolverServiceLoader;
use Spryker\Yves\Security\Loader\Services\UserCheckerServiceLoader;
use Spryker\Yves\Security\Loader\Services\UserProviderPrototypeServiceLoader;
use Spryker\Yves\Security\Loader\Services\UserServiceLoader;
use Spryker\Yves\Security\Loader\Services\UtilsServiceLoader;
use Spryker\Yves\Security\Loader\Services\VotersServiceLoader;
use Spryker\Yves\Security\Loader\ServicesLoader;
use Spryker\Yves\Security\Loader\ServicesLoaderInterface;
use Spryker\Yves\Security\Plugin\Application\SecurityApplicationPlugin;
use Spryker\Yves\Security\Plugin\Validator\UserPasswordValidatorConstraintPlugin;
use Spryker\Yves\Security\Router\SecurityRouterInterface;
use Spryker\Yves\Security\Subscriber\SecurityDispatcherSubscriber;
use Spryker\Yves\Security\Subscriber\SecurityDispatcherSubscriberInterface;
use Spryker\Yves\Security\Validator\UserPasswordValidatorConstraint;
use Spryker\Yves\Security\Validator\UserPasswordValidatorConstraintInterface;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Encoder\NativePasswordEncoder;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategy;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

/**
 * @method \Spryker\Yves\Security\SecurityConfig getConfig()
 */
class SecurityFactory extends AbstractFactory
{
    /**
     * @var \Spryker\Yves\Security\Plugin\Application\SecurityApplicationPlugin|null
     */
    protected $securityApplicationPluginCache;

    /**
     * @return array<\Spryker\Shared\SecurityExtension\Dependency\Plugin\SecurityPluginInterface>
     */
    public function getSecurityPlugins(): array
    {
        return $this->getProvidedDependency(SecurityDependencyProvider::PLUGINS_SECURITY);
    }

    public function createPasswordEncoder(): PasswordEncoderInterface
    {
        return new NativePasswordEncoder(null, null, $this->getConfig()->getBCryptCost());
    }

    public function createPasswordHasher(): PasswordHasherInterface
    {
        return new NativePasswordHasher(null, null, $this->getConfig()->getBCryptCost());
    }

    public function createSessionStrategy(): SessionAuthenticationStrategyInterface
    {
        return new SessionAuthenticationStrategy(SessionAuthenticationStrategy::MIGRATE);
    }

    /**
     * @return list<\Spryker\Shared\SecurityExtension\Dependency\Plugin\SecurityAuthenticationListenerFactoryTypeExpanderPluginInterface>
     */
    public function getSecurityAuthenticationListenerFactoryTypeExpanderPlugins(): array
    {
        return $this->getProvidedDependency(SecurityDependencyProvider::PLUGINS_SECURITY_AUTHENTICATION_LISTENER_FACTORY_TYPE_EXPANDER);
    }

    public function createSecurityConfiguration(): SecurityConfiguration
    {
        return new SecurityConfiguration();
    }

    public function createServicesLoader(): ServicesLoaderInterface
    {
        if (class_exists(AuthenticationProviderManager::class) === true) {
            if ($this->securityApplicationPluginCache === null) {
                $this->securityApplicationPluginCache = new SecurityApplicationPlugin();
            }

            return $this->securityApplicationPluginCache;
        }

        return new ServicesLoader(
            $this->getServiceLoaders(),
        );
    }

    public function createSecurityApplicationBooter(): SecurityApplicationBooterInterface
    {
        if (class_exists(AuthenticationProviderManager::class) === true) {
            if ($this->securityApplicationPluginCache === null) {
                $this->securityApplicationPluginCache = new SecurityApplicationPlugin();
            }

            return $this->securityApplicationPluginCache;
        }

        return new SecurityApplicationBooter(
            $this->createSecurityDispatcherSubscriber(),
            $this->getSecurityRouter(),
        );
    }

    public function createSecurityDispatcherSubscriber(): SecurityDispatcherSubscriberInterface
    {
        return new SecurityDispatcherSubscriber(
            $this->createSecurityConfigurator(),
        );
    }

    public function createSecurityConfigurator(): SecurityConfiguratorInterface
    {
        return new SecurityConfigurator(
            $this->createSecurityConfiguration(),
            $this->getSecurityPlugins(),
        );
    }

    public function getSecurityRouter(): SecurityRouterInterface
    {
        return $this->getProvidedDependency(SecurityDependencyProvider::SERVICE_SECURITY_ROUTERS);
    }

    public function createAuthenticationListener(): AuthenticationListenerInterface
    {
        return new AuthenticationListener(
            $this->getSecurityAuthenticationListenerFactoryTypeExpanderPlugins(),
        );
    }

    /**
     * @return array<\Spryker\Yves\Security\Loader\Services\ServiceLoaderInterface>
     */
    public function getServiceLoaders(): array
    {
        return [
            $this->createAuthorizationCheckerServiceLoader(),
            $this->createTokenStorageServiceLoader(),
            $this->createUserServiceLoader(),
            $this->createAuthenticationManagerServiceLoader(),
            $this->createEncoderServiceLoader(),
            $this->createUserCheckerServiceLoader(),
            $this->createAccessManagerServiceLoader(),
            $this->createVotersServiceLoader(),
            $this->createFirewallServiceLoader(),
            $this->createChannelListenerServiceLoader(),
            $this->createAuthenticationListenerFactoriesServiceLoader(),
            $this->createAccessListenerServiceLoader(),
            $this->createAccessMapServiceLoader(),
            $this->createTrustResolverServiceLoader(),
            $this->createUtilsServiceLoader(),
            $this->createLastErrorServiceLoader(),
            $this->createUserProviderPrototypeServiceLoader(),
            $this->createListenerPrototypeServiceLoader(),
            $this->createAuthenticationListenerPrototypesServiceLoader(),
            $this->createEntryPointPrototypesServiceLoader(),
        ];
    }

    public function createAuthorizationCheckerServiceLoader(): ServiceLoaderInterface
    {
        return new AuthorizationCheckerServiceLoader();
    }

    public function createTokenStorageServiceLoader(): ServiceLoaderInterface
    {
        return new TokenStorageServiceLoader();
    }

    public function createUserServiceLoader(): ServiceLoaderInterface
    {
        return new UserServiceLoader();
    }

    public function createAuthenticationManagerServiceLoader(): ServiceLoaderInterface
    {
        return new AuthenticationManagerServiceLoader(
            $this->createAuthenticatorManager(),
        );
    }

    public function createEncoderServiceLoader(): ServiceLoaderInterface
    {
        return new EncoderServiceLoader(
            $this->createPasswordHasher(),
        );
    }

    public function createUserCheckerServiceLoader(): ServiceLoaderInterface
    {
        return new UserCheckerServiceLoader();
    }

    public function createAccessManagerServiceLoader(): ServiceLoaderInterface
    {
        return new AccessManagerServiceLoader();
    }

    public function createVotersServiceLoader(): ServiceLoaderInterface
    {
        return new VotersServiceLoader(
            $this->createSecurityConfigurator(),
        );
    }

    public function createFirewallServiceLoader(): ServiceLoaderInterface
    {
        return new FirewallServiceLoader(
            $this->createSecurityConfigurator(),
            $this->createAuthenticationListener(),
        );
    }

    public function createChannelListenerServiceLoader(): ServiceLoaderInterface
    {
        return new ChannelListenerServiceLoader(
            $this->getConfig(),
        );
    }

    public function createAuthenticationListenerFactoriesServiceLoader(): ServiceLoaderInterface
    {
        return new AuthenticationListenerFactoriesServiceLoader(
            $this->createAuthenticationListener(),
        );
    }

    public function createAccessListenerServiceLoader(): ServiceLoaderInterface
    {
        return new AccessListenerServiceLoader();
    }

    public function createAccessMapServiceLoader(): ServiceLoaderInterface
    {
        return new AccessMapServiceLoader(
            $this->createSecurityConfigurator(),
        );
    }

    public function createTrustResolverServiceLoader(): ServiceLoaderInterface
    {
        return new TrustResolverServiceLoader();
    }

    public function createUtilsServiceLoader(): ServiceLoaderInterface
    {
        return new UtilsServiceLoader();
    }

    public function createLastErrorServiceLoader(): ServiceLoaderInterface
    {
        return new LastErrorServiceLoader();
    }

    public function createUserProviderPrototypeServiceLoader(): ServiceLoaderInterface
    {
        return new UserProviderPrototypeServiceLoader();
    }

    public function createListenerPrototypeServiceLoader(): ServiceLoaderInterface
    {
        return new ListenerPrototypeServiceLoader();
    }

    public function createAuthenticationListenerPrototypesServiceLoader(): ServiceLoaderInterface
    {
        return new AuthenticationListenerPrototypesServiceLoader(
            $this->createSecurityConfigurator(),
            $this->getSecurityRouter(),
            $this->createAuthenticatorManager(),
        );
    }

    public function createEntryPointPrototypesServiceLoader(): ServiceLoaderInterface
    {
        return new EntryPointPrototypesServiceLoader();
    }

    public function createUserPasswordValidatorConstraint(): UserPasswordValidatorConstraintInterface
    {
        if (class_exists(AuthenticationProviderManager::class) === true) {
            return new UserPasswordValidatorConstraintPlugin();
        }

        return new UserPasswordValidatorConstraint();
    }

    public function createAuthenticatorManager(): AuthenticatorManagerInterface
    {
        return new AuthenticatorManager();
    }
}
