<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CheckoutRestApi;

use Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToCartClientBridge;
use Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToCartsRestApiClientBridge;
use Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToGlossaryStorageClientBridge;
use Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToZedRequestClientBridge;
use Spryker\Glue\Kernel\AbstractBundleDependencyProvider;
use Spryker\Glue\Kernel\Container;

class CheckoutRestApiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const CLIENT_CART = 'CLIENT_CART';
    public const CLIENT_CARTS_REST_API = 'CLIENT_CARTS_REST_API';
    public const CLIENT_ZED_REQUEST = 'CLIENT_ZED_REQUEST';
    public const CLIENT_GLOSSARY_STORAGE = 'CLIENT_GLOSSARY_STORAGE';

    protected const EXCEPTION_MESSAGE_READER_NOT_IMPLEMENTED = 'Reader not implemented on project level';

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    public function provideDependencies(Container $container): Container
    {
        $container = parent::provideDependencies($container);
        $container = $this->addCartClient($container);
        $container = $this->addCartsRestApiClient($container);
        $container = $this->addZedRequestClient($container);
        $container = $this->addGlossaryStorageClient($container);

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addCartClient(Container $container): Container
    {
        $container[static::CLIENT_CART] = function (Container $container) {
            return new CheckoutRestApiToCartClientBridge($container->getLocator()->cart()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addCartsRestApiClient(Container $container): Container
    {
        $container[static::CLIENT_CARTS_REST_API] = function (Container $container) {
            return new CheckoutRestApiToCartsRestApiClientBridge($container->getLocator()->cartsRestApi()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addZedRequestClient(Container $container): Container
    {
        $container[static::CLIENT_ZED_REQUEST] = function (Container $container) {
            return new CheckoutRestApiToZedRequestClientBridge($container->getLocator()->zedRequest()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Glue\Kernel\Container $container
     *
     * @return \Spryker\Glue\Kernel\Container
     */
    protected function addGlossaryStorageClient(Container $container): Container
    {
        $container[static::CLIENT_GLOSSARY_STORAGE] = function (Container $container) {
            return new CheckoutRestApiToGlossaryStorageClientBridge($container->getLocator()->glossaryStorage()->client());
        };

        return $container;
    }
}
