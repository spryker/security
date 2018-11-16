<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CheckoutRestApi;

use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToCartFacadeBridge;
use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToCartsRestApiFacadeBridge;
use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToCheckoutFacadeBridge;
use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToCustomerFacadeBridge;
use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToPaymentFacadeBridge;
use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToQuoteFacadeBridge;
use Spryker\Zed\CheckoutRestApi\Dependency\Facade\CheckoutRestApiToShipmentFacadeBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class CheckoutRestApiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_CART = 'FACADE_CART';
    public const FACADE_CARTS_REST_API = 'FACADE_CARTS_REST_API';
    public const FACADE_CHECKOUT = 'FACADE_CHECKOUT';
    public const FACADE_CUSTOMER = 'FACADE_CUSTOMER';
    public const FACADE_PAYMENT = 'FACADE_PAYMENT';
    public const FACADE_QUOTE = 'FACADE_QUOTE';
    public const FACADE_SHIPMENT = 'FACADE_SHIPMENT';
    public const PLUGINS_QUOTE_MAPPING = 'PLUGINS_QUOTE_MAPPING';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container): Container
    {
        $container = parent::provideBusinessLayerDependencies($container);
        $container = $this->addCartFacade($container);
        $container = $this->addCartsRestApiFacade($container);
        $container = $this->addCheckoutFacade($container);
        $container = $this->addCustomerFacade($container);
        $container = $this->addPaymentFacade($container);
        $container = $this->addQuoteFacade($container);
        $container = $this->addShipmentFacade($container);
        $container = $this->addQuoteMappingPlugins($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCartFacade(Container $container): Container
    {
        $container[static::FACADE_CART] = function (Container $container) {
            return new CheckoutRestApiToCartFacadeBridge($container->getLocator()->cart()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCartsRestApiFacade(Container $container): Container
    {
        $container[static::FACADE_CARTS_REST_API] = function (Container $container) {
            return new CheckoutRestApiToCartsRestApiFacadeBridge($container->getLocator()->cartsRestApi()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCheckoutFacade(Container $container): Container
    {
        $container[static::FACADE_CHECKOUT] = function (Container $container) {
            return new CheckoutRestApiToCheckoutFacadeBridge($container->getLocator()->checkout()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCustomerFacade(Container $container): Container
    {
        $container[static::FACADE_CUSTOMER] = function (Container $container) {
            return new CheckoutRestApiToCustomerFacadeBridge($container->getLocator()->customer()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addPaymentFacade(Container $container): Container
    {
        $container[static::FACADE_PAYMENT] = function (Container $container) {
            return new CheckoutRestApiToPaymentFacadeBridge($container->getLocator()->payment()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addQuoteFacade(Container $container): Container
    {
        $container[static::FACADE_QUOTE] = function (Container $container) {
            return new CheckoutRestApiToQuoteFacadeBridge($container->getLocator()->quote()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addShipmentFacade(Container $container): Container
    {
        $container[static::FACADE_SHIPMENT] = function (Container $container) {
            return new CheckoutRestApiToShipmentFacadeBridge($container->getLocator()->shipment()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addQuoteMappingPlugins(Container $container): Container
    {
        $container[static::PLUGINS_QUOTE_MAPPING] = function () {
            return $this->getQuoteMappingPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\CheckoutRestApiExtension\Dependency\Plugin\QuoteMappingPluginInterface[]
     */
    protected function getQuoteMappingPlugins(): array
    {
        return [];
    }
}
