<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductPackagingUnitStorage;

use Spryker\Client\Kernel\AbstractDependencyProvider;
use Spryker\Client\Kernel\Container;
use Spryker\Client\ProductPackagingUnitStorage\Dependency\Client\PriceProductStorageToPriceProductBridge;
use Spryker\Client\ProductPackagingUnitStorage\Dependency\Client\PriceProductStorageToStorageBridge;
use Spryker\Client\ProductPackagingUnitStorage\Dependency\Client\PriceProductStorageToStoreClientBridge;
use Spryker\Client\ProductPackagingUnitStorage\Dependency\Service\PriceProductStorageToSynchronizationServiceBridge;

class PriceProductStorageDependencyProvider extends AbstractDependencyProvider
{
    const CLIENT_STORAGE = 'CLIENT_STORAGE';
    const CLIENT_STORE = 'CLIENT_STORE';
    const CLIENT_PRICE_PRODUCT = 'CLIENT_PRICE_PRODUCT';
    const SERVICE_SYNCHRONIZATION = 'SERVICE_SYNCHRONIZATION';

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    public function provideServiceLayerDependencies(Container $container)
    {
        $container = $this->addStorageClient($container);
        $container = $this->addPriceProductClient($container);
        $container = $this->addSynchronizationService($container);
        $container = $this->addStoreClient($container);

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addStorageClient(Container $container): Container
    {
        $container[self::CLIENT_STORAGE] = function (Container $container) {
            return new PriceProductStorageToStorageBridge($container->getLocator()->storage()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addPriceProductClient(Container $container): Container
    {
        $container[self::CLIENT_PRICE_PRODUCT] = function (Container $container) {
            return new PriceProductStorageToPriceProductBridge($container->getLocator()->priceProduct()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addSynchronizationService(Container $container): Container
    {
        $container[self::SERVICE_SYNCHRONIZATION] = function (Container $container) {
            return new PriceProductStorageToSynchronizationServiceBridge($container->getLocator()->synchronization()->service());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addStoreClient(Container $container): Container
    {
        $container[static::CLIENT_STORE] = function (Container $container) {
            return new PriceProductStorageToStoreClientBridge($container->getLocator()->store()->client());
        };

        return $container;
    }
}
