<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSetStorage;

use Spryker\Shared\Kernel\Store;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\ProductSetStorage\Dependency\Facade\ProductSetStorageToEventBehaviorFacadeBridge;
use Spryker\Zed\ProductSetStorage\Dependency\QueryContainer\ProductSetStorageToProductImageQueryContainerBridge;
use Spryker\Zed\ProductSetStorage\Dependency\QueryContainer\ProductSetStorageToProductSetQueryContainerBridge;
use Spryker\Zed\ProductSetStorage\Dependency\Service\ProductSetStorageToUtilSanitizeServiceBridge;

class ProductSetStorageDependencyProvider extends AbstractBundleDependencyProvider
{
    const QUERY_CONTAINER_PRODUCT_SET = 'QUERY_CONTAINER_PRODUCT_SET';
    const QUERY_CONTAINER_PRODUCT_IMAGE = 'QUERY_CONTAINER_PRODUCT_IMAGE';
    const SERVICE_UTIL_SANITIZE = 'SERVICE_UTIL_SANITIZE';
    const FACADE_EVENT_BEHAVIOR = 'FACADE_EVENT_BEHAVIOR';
    const FACADE_PRODUCT = 'FACADE_PRODUCT';
    const STORE = 'STORE';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        $container[static::SERVICE_UTIL_SANITIZE] = function (Container $container) {
            return new ProductSetStorageToUtilSanitizeServiceBridge($container->getLocator()->utilSanitize()->service());
        };

        $container[static::FACADE_EVENT_BEHAVIOR] = function (Container $container) {
            return new ProductSetStorageToEventBehaviorFacadeBridge($container->getLocator()->eventBehavior()->facade());
        };

        $container[static::STORE] = function (Container $container) {
            return Store::getInstance();
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
        $container[static::QUERY_CONTAINER_PRODUCT_SET] = function (Container $container) {
            return new ProductSetStorageToProductSetQueryContainerBridge($container->getLocator()->productSet()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_PRODUCT_IMAGE] = function (Container $container) {
            return new ProductSetStorageToProductImageQueryContainerBridge($container->getLocator()->productImage()->queryContainer());
        };

        return $container;
    }
}
