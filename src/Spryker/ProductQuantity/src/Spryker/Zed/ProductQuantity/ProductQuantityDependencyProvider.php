<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductQuantity;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\ProductQuantity\Dependency\Service\ProductQuantityToUtilQuantityServiceBridge;

/**
 * @method \Spryker\Zed\ProductQuantity\ProductQuantityConfig getConfig()
 */
class ProductQuantityDependencyProvider extends AbstractBundleDependencyProvider
{
    public const SERVICE_UTIL_QUANTITY = 'SERVICE_UTIL_QUANTITY';
    public const SERVICE_PRODUCT_QUANTITY = 'SERVICE_PRODUCT_QUANTITY';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container): Container
    {
        $container = parent::provideBusinessLayerDependencies($container);
        $container = $this->addProductQuantityService($container);
        $container = $this->addUtilQuantityService($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addUtilQuantityService(Container $container): Container
    {
        $container[static::SERVICE_UTIL_QUANTITY] = function (Container $container) {
            return new ProductQuantityToUtilQuantityServiceBridge(
                $container->getLocator()->utilQuantity()->service()
            );
        };

//        $container = $this->addProductQuantityService($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function providePersistenceLayerDependencies(Container $container): Container
    {
        $container = parent::providePersistenceLayerDependencies($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addProductQuantityService(Container $container): Container
    {
        $container[static::SERVICE_PRODUCT_QUANTITY] = function (Container $container) {
            return $container->getLocator()->productQuantity()->service();
        };

        return $container;
    }
}
