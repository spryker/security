<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityBridge;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToLocaleBridge;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceBridge;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductBridge;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductImageBridge;
use Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerBridge;
use Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToProductQueryContainerBridge;
use Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToSalesQueryContainerBridge;
use Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToStockQueryContainerBridge;

class ProductBundleDependencyProvider extends AbstractBundleDependencyProvider
{
    const FACADE_PRODUCT = 'product facade';
    const FACADE_PRICE = 'price facade';
    const FACADE_LOCALE = 'locale facade';
    const FACADE_AVAILABILITY = 'facade availability';
    const FACADE_PRODUCT_IMAGE = 'product image facade';

    const QUERY_CONTAINER_AVAILABILITY = 'availability query container';
    const QUERY_CONTAINER_SALES = 'sales query container';
    const QUERY_CONTAINER_STOCK = 'stock query container';
    const QUERY_CONTAINER_PRODUCT = 'product query container';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container[static::FACADE_PRODUCT] = function (Container $container) {
            return new ProductBundleToProductBridge($container->getLocator()->product()->facade());
        };

        $container[static::FACADE_PRICE] = function (Container $container) {
            return new ProductBundleToPriceBridge($container->getLocator()->price()->facade());
        };

        $container[static::FACADE_LOCALE] = function (Container $container) {
            return new ProductBundleToLocaleBridge($container->getLocator()->locale()->facade());
        };

        $container[static::FACADE_AVAILABILITY] = function (Container $container) {
            return new ProductBundleToAvailabilityBridge($container->getLocator()->availability()->facade());
        };

        $container[static::QUERY_CONTAINER_AVAILABILITY] = function (Container $container) {
            return new ProductBundleToAvailabilityQueryContainerBridge($container->getLocator()->availability()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_SALES] = function (Container $container) {
            return new ProductBundleToSalesQueryContainerBridge($container->getLocator()->sales()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_STOCK] = function (Container $container) {
            return new ProductBundleToStockQueryContainerBridge($container->getLocator()->stock()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_PRODUCT] = function (Container $container) {
            return new ProductBundleToProductQueryContainerBridge($container->getLocator()->product()->queryContainer());
        };

        $container[static::FACADE_PRODUCT_IMAGE] = function (Container $container) {
            return new ProductBundleToProductImageBridge($container->getLocator()->productImage()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function providePersistenceLayerDependencies(Container $container)
    {
        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        return $container;
    }
}
