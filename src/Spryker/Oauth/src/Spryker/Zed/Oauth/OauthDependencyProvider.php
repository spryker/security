<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Oauth;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

/**
 * @method \Spryker\Zed\Oauth\OauthConfig getConfig()
 */
class OauthDependencyProvider extends AbstractBundleDependencyProvider
{
    public const PLUGIN_USER_PROVIDER = 'PLUGIN_USER_PROVIDER';
    public const PLUGIN_SCOPE_PROVIDER = 'PLUGIN_SCOPE_PROVIDER';
    public const PLUGINS_GRANT_TYPE_PROVIDER = 'PLUGINS_GRANT_TYPE_PROVIDER';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container): Container
    {
        $container = $this->addUserProviderPlugins($container);
        $container = $this->addScopeProviderPlugins($container);
        $container = $this->addGrantTypeProviderPlugins($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addUserProviderPlugins(Container $container): Container
    {
        $container[static::PLUGIN_USER_PROVIDER] = function (Container $container) {
            return $this->getUserProviderPlugins();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addScopeProviderPlugins(Container $container): Container
    {
        $container[static::PLUGIN_SCOPE_PROVIDER] = function (Container $container) {
            return $this->getScopeProviderPlugins();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addGrantTypeProviderPlugins(Container $container): Container
    {
        $container[static::PLUGINS_GRANT_TYPE_PROVIDER] = function (Container $container) {
            return $this->getGrantTypeProviderPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthUserProviderPluginInterface[]
     */
    protected function getUserProviderPlugins(): array
    {
        return [];
    }

    /**
     * @return \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthScopeProviderPluginInterface[]
     */
    protected function getScopeProviderPlugins(): array
    {
        return [];
    }

    /**
     * @return \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthGrantTypeProviderPluginInterface[]
     */
    protected function getGrantTypeProviderPlugins(): array
    {
        return [];
    }
}
