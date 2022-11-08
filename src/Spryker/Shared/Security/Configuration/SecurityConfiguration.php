<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Security\Configuration;

use Spryker\Shared\Security\Exception\FirewallNotFoundException;
use Spryker\Shared\Security\Exception\SecurityConfigurationException;
use Spryker\Shared\SecurityExtension\Configuration\SecurityBuilderInterface;
use Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class SecurityConfiguration implements SecurityBuilderInterface, SecurityConfigurationInterface
{
    /**
     * @var array
     */
    protected $firewalls = [];

    /**
     * @var array
     */
    protected $mergableFirewalls = [];

    /**
     * @var array
     */
    protected $accessRules = [];

    /**
     * @var array
     */
    protected $roleHierarchies = [];

    /**
     * @var array<callable>
     */
    protected $authenticationSuccessHandlers = [];

    /**
     * @var array<callable>
     */
    protected $authenticationFailureHandlers = [];

    /**
     * @var array<callable>
     */
    protected $logoutHandlers = [];

    /**
     * @var array<callable>
     */
    protected $accessDeniedHandlers = [];

    /**
     * @var array
     */
    protected $eventSubscribers = [];

    /**
     * @var bool
     */
    protected $isFrozen = false;

    /**
     * @param string $firewallName
     * @param array<string, mixed> $configuration
     *
     * @return $this
     */
    public function addFirewall(string $firewallName, array $configuration)
    {
        $this->assertNotFrozen();

        $this->firewalls[$firewallName] = $configuration;

        return $this;
    }

    /**
     * @param string $firewallName
     * @param array<string, mixed> $configuration
     *
     * @return $this
     */
    public function mergeFirewall(string $firewallName, array $configuration)
    {
        $this->assertNotFrozen();

        if (array_key_exists($firewallName, $this->mergableFirewalls)) {
            $configuration += $this->mergableFirewalls[$firewallName];
        }

        $this->mergableFirewalls[$firewallName] = $configuration;

        return $this;
    }

    /**
     * @return array
     */
    public function getFirewalls(): array
    {
        $this->assertFrozen();

        return $this->firewalls;
    }

    /**
     * @param array $accessRules
     *
     * @return $this
     */
    public function addAccessRules(array $accessRules)
    {
        $this->assertNotFrozen();

        $this->accessRules = array_merge($this->accessRules, $accessRules);

        return $this;
    }

    /**
     * @return array
     */
    public function getAccessRules(): array
    {
        $this->assertFrozen();

        return $this->accessRules;
    }

    /**
     * @param array $roleHierarchy
     *
     * @return $this
     */
    public function addRoleHierarchy(array $roleHierarchy)
    {
        $this->assertNotFrozen();

        foreach ($roleHierarchy as $mainRole => $hierarchy) {
            $this->roleHierarchies[$mainRole] = $hierarchy;
        }

        return $this;
    }

    /**
     * @return array
     */
    public function getRoleHierarchies(): array
    {
        $this->assertFrozen();

        return $this->roleHierarchies;
    }

    /**
     * @param string $firewallName
     * @param callable $authenticationSuccessHandler
     *
     * @return $this
     */
    public function addAuthenticationSuccessHandler(string $firewallName, callable $authenticationSuccessHandler)
    {
        $this->assertNotFrozen();

        $this->authenticationSuccessHandlers[$firewallName] = $authenticationSuccessHandler;

        return $this;
    }

    /**
     * @return array<callable>
     */
    public function getAuthenticationSuccessHandlers(): array
    {
        $this->assertFrozen();

        return $this->authenticationSuccessHandlers;
    }

    /**
     * @param string $firewallName
     * @param callable $authenticationFailureHandler
     *
     * @return $this
     */
    public function addAuthenticationFailureHandler(string $firewallName, callable $authenticationFailureHandler)
    {
        $this->assertNotFrozen();

        $this->authenticationFailureHandlers[$firewallName] = $authenticationFailureHandler;

        return $this;
    }

    /**
     * @return array<callable>
     */
    public function getAuthenticationFailureHandlers(): array
    {
        $this->assertFrozen();

        return $this->authenticationFailureHandlers;
    }

    /**
     * @deprecated Use {@link \Spryker\Shared\EventDispatcherExtension\Dependency\Plugin\EventDispatcherPluginInterface::extend()} instead. Since symfony/security-core 5.1 an event listener or subscriber instead.
     *
     * @param string $firewallName
     * @param callable $logoutHandler
     *
     * @throws \Spryker\Shared\Security\Exception\SecurityConfigurationException
     *
     * @return $this
     */
    public function addLogoutHandler(string $firewallName, callable $logoutHandler)
    {
        if (class_exists(LogoutEvent::class)) {
            throw new SecurityConfigurationException(sprintf(
                'Adding a logout handler is forbidden, please add an event listener or subscriber. Use a "\Spryker\Shared\EventDispatcherExtension\Dependency\Plugin\EventDispatcherPluginInterface" with the event "%s" to add your logout handling.',
                LogoutEvent::class,
            ));
        }

        $this->assertNotFrozen();

        $this->logoutHandlers[$firewallName] = $logoutHandler;

        return $this;
    }

    /**
     * @return array<callable>
     */
    public function getLogoutHandlers(): array
    {
        $this->assertFrozen();

        return $this->logoutHandlers;
    }

    /**
     * @param string $firewallName
     * @param callable $accessDeniedHandler
     *
     * @return \Spryker\Shared\SecurityExtension\Configuration\SecurityBuilderInterface
     */
    public function addAccessDeniedHandler(string $firewallName, callable $accessDeniedHandler): SecurityBuilderInterface
    {
        $this->assertNotFrozen();

        $this->accessDeniedHandlers[$firewallName] = $accessDeniedHandler;

        return $this;
    }

    /**
     * @return array<callable>
     */
    public function getAccessDeniedHandlers(): array
    {
        $this->assertFrozen();

        return $this->accessDeniedHandlers;
    }

    /**
     * @param callable $eventSubscriber
     *
     * @return \Spryker\Shared\SecurityExtension\Configuration\SecurityBuilderInterface
     */
    public function addEventSubscriber(callable $eventSubscriber): SecurityBuilderInterface
    {
        $this->assertNotFrozen();

        $this->eventSubscribers[] = $eventSubscriber;

        return $this;
    }

    /**
     * @return array
     */
    public function getEventSubscribers(): array
    {
        $this->assertFrozen();

        return $this->eventSubscribers;
    }

    /**
     * @throws \Spryker\Shared\Security\Exception\FirewallNotFoundException
     *
     * @return \Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface
     */
    public function getConfiguration(): SecurityConfigurationInterface
    {
        $this->assertNotFrozen();

        $this->isFrozen = true;

        foreach ($this->mergableFirewalls as $firewallName => $configuration) {
            if (!isset($this->firewalls[$firewallName])) {
                throw new FirewallNotFoundException(sprintf('You tried to merge a firewall "%s" which is not configured.', $firewallName));
            }

            $this->firewalls[$firewallName] = array_merge_recursive($this->firewalls[$firewallName], $configuration);
        }

        return $this;
    }

    /**
     * @throws \Spryker\Shared\Security\Exception\SecurityConfigurationException
     *
     * @return void
     */
    protected function assertNotFrozen(): void
    {
        if ($this->isFrozen) {
            throw new SecurityConfigurationException('The configuration is marked as frozen and can\'t be changed.');
        }
    }

    /**
     * @throws \Spryker\Shared\Security\Exception\SecurityConfigurationException
     *
     * @return void
     */
    protected function assertFrozen(): void
    {
        if (!$this->isFrozen) {
            throw new SecurityConfigurationException('Please use "\Spryker\Shared\SecurityExtension\Configuration\SecurityConfiguration::getConfiguration()" to retrieve the security configuration.');
        }
    }
}
