<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Stock;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\Stock\Dependency\Facade\StockToProductBridge;
use Spryker\Zed\Stock\Dependency\Facade\StockToStoreFacadeBridge;
use Spryker\Zed\Stock\Dependency\Facade\StockToTouchBridge;

class StockDependencyProvider extends AbstractBundleDependencyProvider
{
    const FACADE_TOUCH = 'FACADE_TOUCH';
    const FACADE_PRODUCT = 'FACADE_PRODUCT';
    const FACADE_STORE = 'FACADE_STORE';

    const PLUGINS_STOCK_UPDATE = 'PLUGINS_STOCK_UPDATE';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container = $this->addTouchFacade($container);
        $container = $this->addProductFacade($container);
        $container = $this->addStockUpdatePlugins($container);
        $container = $this->addStoreFacade($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addStoreFacade(Container $container)
    {
        $container[static::FACADE_STORE] = function (Container $container) {
            return new StockToStoreFacadeBridge($container->getLocator()->store()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addStockUpdatePlugins(Container $container): Container
    {
        $container[static::PLUGINS_STOCK_UPDATE] = function (Container $container) {
            return $this->getStockUpdateHandlerPlugins($container);
        };
        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addProductFacade(Container $container): Container
    {
        $container[static::FACADE_PRODUCT] = function (Container $container) {
            return new StockToProductBridge($container->getLocator()->product()->facade());
        };
        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addTouchFacade(Container $container): Container
    {
        $container[static::FACADE_TOUCH] = function (Container $container) {
            return new StockToTouchBridge($container->getLocator()->touch()->facade());
        };
        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Stock\Dependency\Plugin\StockUpdateHandlerPluginInterface[]
     */
    protected function getStockUpdateHandlerPlugins(Container $container)
    {
        return [];
    }
}
