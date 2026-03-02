<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security\Configurator;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\Security\Configuration\SecurityConfiguration;
use Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface;

class SecurityConfigurator implements SecurityConfiguratorInterface
{
    /**
     * @var \Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface|null
     */
    protected static ?SecurityConfigurationInterface $securityConfiguration = null;

    /**
     * @var \Spryker\Shared\Security\Configuration\SecurityConfiguration
     */
    protected $sharedSecurityConfiguration;

    /**
     * @var array<\Spryker\Shared\SecurityExtension\Dependency\Plugin\SecurityPluginInterface>
     */
    protected array $securityPlugins;

    /**
     * @param \Spryker\Shared\Security\Configuration\SecurityConfiguration $sharedSecurityConfiguration
     * @param array<\Spryker\Shared\SecurityExtension\Dependency\Plugin\SecurityPluginInterface> $securityPlugins
     */
    public function __construct(
        SecurityConfiguration $sharedSecurityConfiguration,
        array $securityPlugins
    ) {
        $this->sharedSecurityConfiguration = $sharedSecurityConfiguration;
        $this->securityPlugins = $securityPlugins;
    }

    public function getSecurityConfiguration(ContainerInterface $container): SecurityConfigurationInterface
    {
        if (static::$securityConfiguration === null) {
            static::$securityConfiguration = $this->getSecurityConfigurationFromPlugins($container);
        }

        return static::$securityConfiguration;
    }

    protected function getSecurityConfigurationFromPlugins(ContainerInterface $container): SecurityConfigurationInterface
    {
        $sharedSecurityConfiguration = $this->sharedSecurityConfiguration;

        foreach ($this->securityPlugins as $securityPlugin) {
            $sharedSecurityConfiguration = $securityPlugin->extend($sharedSecurityConfiguration, $container);
        }

        return $sharedSecurityConfiguration->getConfiguration();
    }
}
