<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ContentGui;

use Orm\Zed\Content\Persistence\Base\SpyContentQuery;
use Spryker\Zed\ContentGui\Dependency\Facade\ContentGuiToContentFacadeBridge;
use Spryker\Zed\ContentGui\Dependency\Facade\ContentGuiToLocaleFacadeBridge;
use Spryker\Zed\ContentGui\Dependency\Service\ContentGuiToUtilEncodingBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

/**
 * @method \Spryker\Zed\ContentGui\ContentGuiConfig getConfig()
 */
class ContentGuiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const PLUGINS_CONTENT_ITEM = 'PLUGINS_CONTENT_ITEM';
    public const PROPEL_QUERY_CONTENT = 'PROPEL_QUERY_CONTENT';
    public const SERVICE_UTIL_ENCODING = 'SERVICE_UTIL_ENCODING';
    public const FACADE_LOCALE = 'FACADE_LOCALE';
    public const FACADE_CONTENT = 'FACADE_CONTENT';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container): Container
    {
        $container = parent::provideCommunicationLayerDependencies($container);

        $container = $this->addPropelContentQuery($container);
        $container = $this->addLocaleFacadeService($container);
        $container = $this->addContentFacade($container);
        $container = $this->addContentPlugins($container);
        $container = $this->addUtilEncoding($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addContentPlugins(Container $container): Container
    {
        $container[static::PLUGINS_CONTENT_ITEM] = function () {
            return $this->getContentPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\ContentGuiExtension\Dependency\Plugin\ContentPluginInterface[]
     */
    protected function getContentPlugins(): array
    {
        return [];
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addLocaleFacadeService(Container $container): Container
    {
        $container[static::FACADE_LOCALE] = function (Container $container) {
            return new ContentGuiToLocaleFacadeBridge($container->getLocator()->locale()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addPropelContentQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_CONTENT] = function () {
            return SpyContentQuery::create();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addContentFacade(Container $container): Container
    {
        $container[static::FACADE_CONTENT] = function (Container $container) {
            return new ContentGuiToContentFacadeBridge(
                $container->getLocator()->content()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addUtilEncoding(Container $container): Container
    {
        $container[static::SERVICE_UTIL_ENCODING] = function (Container $container) {
            return new ContentGuiToUtilEncodingBridge($container->getLocator()->utilEncoding()->service());
        };

        return $container;
    }
}
