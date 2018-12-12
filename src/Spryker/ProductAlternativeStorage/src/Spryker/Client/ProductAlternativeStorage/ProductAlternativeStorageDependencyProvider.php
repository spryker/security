<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductAlternativeStorage;

use Spryker\Client\Kernel\AbstractDependencyProvider;
use Spryker\Client\Kernel\Container;
use Spryker\Client\ProductAlternativeStorage\Dependency\Client\ProductAlternativeStorageToProductStorageClientBridge;
use Spryker\Client\ProductAlternativeStorage\Dependency\Client\ProductAlternativeStorageToStorageClientBridge;
use Spryker\Client\ProductAlternativeStorage\Dependency\Service\ProductAlternativeStorageToSynchronizationServiceBridge;

/**
 * @method \Spryker\Client\ProductAlternativeStorage\ProductAlternativeStorageConfig getConfig()
 */
class ProductAlternativeStorageDependencyProvider extends AbstractDependencyProvider
{
    public const CLIENT_STORAGE = 'CLIENT_STORAGE';
    public const SERVICE_SYNCHRONIZATION = 'SERVICE_SYNCHRONIZATION';
    public const PLUGINS_ALTERNATIVE_PRODUCT_APPLICABLE_CHECK = 'PLUGINS_ALTERNATIVE_PRODUCT_APPLICABLE_CHECK';
    public const CLIENT_PRODUCT_STORAGE = 'CLIENT_PRODUCT_STORAGE';

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    public function provideServiceLayerDependencies(Container $container): Container
    {
        $container = parent::provideServiceLayerDependencies($container);
        $container = $this->addStorageClient($container);
        $container = $this->addSynchronizationService($container);
        $container = $this->addProductStorageClient($container);
        $container = $this->addAlternativeProductApplicableCheckPlugins($container);

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addStorageClient(Container $container): Container
    {
        $container[static::CLIENT_STORAGE] = function (Container $container) {
            return new ProductAlternativeStorageToStorageClientBridge($container->getLocator()->storage()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addProductStorageClient(Container $container): Container
    {
        $container[static::CLIENT_PRODUCT_STORAGE] = function (Container $container) {
            return new ProductAlternativeStorageToProductStorageClientBridge(
                $container->getLocator()->productStorage()->client()
            );
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
        $container[static::SERVICE_SYNCHRONIZATION] = function (Container $container) {
            return new ProductAlternativeStorageToSynchronizationServiceBridge(
                $container->getLocator()->synchronization()->service()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addAlternativeProductApplicableCheckPlugins(Container $container): Container
    {
        $container[static::PLUGINS_ALTERNATIVE_PRODUCT_APPLICABLE_CHECK] = function (Container $container) {
            return $this->getAlternativeProductApplicableCheckPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Client\ProductAlternativeStorageExtension\Dependency\Plugin\AlternativeProductApplicablePluginInterface[]
     */
    protected function getAlternativeProductApplicableCheckPlugins(): array
    {
        return [];
    }
}
