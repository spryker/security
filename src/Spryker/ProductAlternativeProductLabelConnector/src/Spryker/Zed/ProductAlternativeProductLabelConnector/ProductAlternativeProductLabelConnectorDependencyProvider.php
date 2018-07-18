<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAlternativeProductLabelConnector;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\ProductAlternativeProductLabelConnector\Dependency\Facade\ProductAlternativeProductLabelConnectorToAvailabilityFacadeBridge;
use Spryker\Zed\ProductAlternativeProductLabelConnector\Dependency\Facade\ProductAlternativeProductLabelConnectorToLocaleFacadeBridge;
use Spryker\Zed\ProductAlternativeProductLabelConnector\Dependency\Facade\ProductAlternativeProductLabelConnectorToProductAlternativeFacadeBridge;
use Spryker\Zed\ProductAlternativeProductLabelConnector\Dependency\Facade\ProductAlternativeProductLabelConnectorToProductBridge;
use Spryker\Zed\ProductAlternativeProductLabelConnector\Dependency\Facade\ProductAlternativeProductLabelConnectorToProductLabelBridge;

class ProductAlternativeProductLabelConnectorDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_PRODUCT_LABEL = 'FACADE_PRODUCT_LABEL';
    public const FACADE_PRODUCT_ALTERNATIVE = 'FACADE_PRODUCT_ALTERNATIVE';
    public const FACADE_AVAILABILITY = 'FACADE_AVAILABILITY';
    public const FACADE_PRODUCT = 'FACADE_PRODUCT';
    public const FACADE_LOCALE = 'FACADE_LOCALE';
    public const PRODUCT_CONCRETE_DISCONTINUED_CHECK_PLUGINS = 'PRODUCT_CONCRETE_DISCONTINUED_CHECK_PLUGINS';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container): Container
    {
        $container = parent::provideBusinessLayerDependencies($container);
        $container = $this->addProductLabelFacade($container);
        $container = $this->addProductFacade($container);
        $container = $this->addProductAlternativeFacade($container);
        $container = $this->addAvailabilityFacade($container);
        $container = $this->addLocaleFacade($container);
        $container = $this->addProductConcreteDiscontinuedCheckPlugins($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addProductLabelFacade(Container $container): Container
    {
        $container[static::FACADE_PRODUCT_LABEL] = function (Container $container) {
            return new ProductAlternativeProductLabelConnectorToProductLabelBridge(
                $container->getLocator()->productLabel()->facade()
            );
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
            return new ProductAlternativeProductLabelConnectorToProductBridge(
                $container->getLocator()->product()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addProductAlternativeFacade(Container $container): Container
    {
        $container[static::FACADE_PRODUCT_ALTERNATIVE] = function (Container $container) {
            return new ProductAlternativeProductLabelConnectorToProductAlternativeFacadeBridge(
                $container->getLocator()->productAlternative()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addLocaleFacade(Container $container): Container
    {
        $container[static::FACADE_LOCALE] = function (Container $container) {
            return new ProductAlternativeProductLabelConnectorToLocaleFacadeBridge(
                $container->getLocator()->locale()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addAvailabilityFacade(Container $container): Container
    {
        $container[static::FACADE_AVAILABILITY] = function (Container $container) {
            return new ProductAlternativeProductLabelConnectorToAvailabilityFacadeBridge(
                $container->getLocator()->availability()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addProductConcreteDiscontinuedCheckPlugins(Container $container)
    {
        $container[static::PRODUCT_CONCRETE_DISCONTINUED_CHECK_PLUGINS] = function () {
            return $this->getProductConcreteDiscontinuedCheckPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\ProductAlternativeExtension\Dependency\Plugin\ProductConcreteDiscontinuedCheckPluginInterface[]
     */
    protected function getProductConcreteDiscontinuedCheckPlugins()
    {
        return [];
    }
}
