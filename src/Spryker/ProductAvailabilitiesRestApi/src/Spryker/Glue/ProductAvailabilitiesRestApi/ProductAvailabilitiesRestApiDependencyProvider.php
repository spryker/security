<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductAvailabilitiesRestApi;

use Spryker\Glue\Kernel\AbstractBundleDependencyProvider;
use Spryker\Glue\Kernel\Container;
use Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToAvailabilityResourceAliasStorageClientBridge;
use Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToAvailabilityStorageClientBridge;
use Spryker\Glue\ProductAvailabilitiesRestApi\Dependency\Client\ProductAvailabilitiesRestApiToProductResourceAliasStorageBridge;

class ProductAvailabilitiesRestApiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const CLIENT_AVAILABILITY_RESOURCE_ALIAS_STORAGE = 'CLIENT_AVAILABILITY_RESOURCE_ALIAS_STORAGE';
    public const CLIENT_AVAILABILITY_STORAGE = 'CLIENT_AVAILABILITY_STORAGE';
    public const CLIENT_PRODUCT_RESOURCE_ALIAS_STORAGE = 'CLIENT_PRODUCT_RESOURCE_ALIAS_STORAGE';

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    public function provideDependencies(Container $container): Container
    {
        $container = $this->addProductAvailabilitiesRestApiStorageClient($container);
        $container = $this->addAvailabilityStorageClient($container);
        $container = $this->addProductResourceAliasStorageClient($container);

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addProductAvailabilitiesRestApiStorageClient(Container $container): Container
    {
        $container[static::CLIENT_AVAILABILITY_RESOURCE_ALIAS_STORAGE] = function (Container $container) {
            return new ProductAvailabilitiesRestApiToAvailabilityResourceAliasStorageClientBridge(
                $container->getLocator()->availabilityResourceAliasStorage()->client()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addAvailabilityStorageClient(Container $container): Container
    {
        $container[static::CLIENT_AVAILABILITY_STORAGE] = function (Container $container) {
            return new ProductAvailabilitiesRestApiToAvailabilityStorageClientBridge(
                $container->getLocator()->availabilityStorage()->client()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addProductResourceAliasStorageClient(Container $container): Container
    {
        $container[static::CLIENT_PRODUCT_RESOURCE_ALIAS_STORAGE] = function (Container $container) {
            return new ProductAvailabilitiesRestApiToProductResourceAliasStorageBridge($container->getLocator()->productResourceAliasStorage()->client());
        };

        return $container;
    }
}
