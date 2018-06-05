<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToEventBehaviorFacadeBridge;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToPriceProductFacadeBridge;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToStoreFacadeBridge;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\QueryContainer\PriceProductStorageToPriceProductQueryContainerBridge;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\QueryContainer\PriceProductStorageToProductQueryContainerBridge;

class ProductPackagingUnitStorageDependencyProvider extends AbstractBundleDependencyProvider
{
    const QUERY_CONTAINER_PRICE_PRODUCT = 'QUERY_CONTAINER_PRICE_PRODUCT';
    const QUERY_CONTAINER_PRODUCT = 'QUERY_CONTAINER_PRODUCT';
    const FACADE_PRICE_PRODUCT = 'FACADE_PRICE_PRODUCT';
    const FACADE_EVENT_BEHAVIOR = 'FACADE_EVENT_BEHAVIOR';
    const FACADE_STORE = 'FACADE_STORE';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        $container[static::FACADE_EVENT_BEHAVIOR] = function (Container $container) {
            return new PriceProductStorageToEventBehaviorFacadeBridge($container->getLocator()->eventBehavior()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container[static::FACADE_PRICE_PRODUCT] = function (Container $container) {
            return new PriceProductStorageToPriceProductFacadeBridge($container->getLocator()->priceProduct()->facade());
        };

        $container[static::FACADE_STORE] = function (Container $container) {
            return new PriceProductStorageToStoreFacadeBridge($container->getLocator()->store()->facade());
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
        $container[static::QUERY_CONTAINER_PRODUCT] = function (Container $container) {
            return new PriceProductStorageToProductQueryContainerBridge($container->getLocator()->product()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_PRICE_PRODUCT] = function (Container $container) {
            return new PriceProductStorageToPriceProductQueryContainerBridge($container->getLocator()->priceProduct()->queryContainer());
        };

        return $container;
    }
}
