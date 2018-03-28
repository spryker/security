<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\MultiCart;

use Spryker\Client\Kernel\AbstractDependencyProvider;
use Spryker\Client\Kernel\Container;
use Spryker\Client\MultiCart\Dependency\Client\MultiCartToMessengerClientBridge;
use Spryker\Client\MultiCart\Dependency\Client\MultiCartToPersistentCartClientBridge;
use Spryker\Client\MultiCart\Dependency\Client\MultiCartToQuoteClientBridge;
use Spryker\Client\MultiCart\Dependency\Client\MultiCartToSessionClientBridge;
use Spryker\Client\MultiCart\Dependency\Client\MultiCartToZedRequestClientBridge;

class MultiCartDependencyProvider extends AbstractDependencyProvider
{
    public const CLIENT_MESSENGER = 'CLIENT_MESSENGER';
    public const CLIENT_PERSISTENT_CART = 'CLIENT_PERSISTENT_CART';
    public const CLIENT_QUOTE = 'CLIENT_QUOTE';
    public const CLIENT_SESSION = 'CLIENT_SESSION';
    public const CLIENT_ZED_REQUEST = 'CLIENT_ZED_REQUEST';

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    public function provideServiceLayerDependencies(Container $container)
    {
        $container = $this->addMessengerClient($container);
        $container = $this->addPersistentCartClient($container);
        $container = $this->addQuoteClient($container);
        $container = $this->addSessionClient($container);
        $container = $this->addZedRequestClient($container);

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addSessionClient(Container $container)
    {
        $container[static::CLIENT_SESSION] = function (Container $container) {
            return new MultiCartToSessionClientBridge($container->getLocator()->session()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addQuoteClient(Container $container)
    {
        $container[static::CLIENT_QUOTE] = function (Container $container) {
            return new MultiCartToQuoteClientBridge($container->getLocator()->quote()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addZedRequestClient(Container $container)
    {
        $container[static::CLIENT_ZED_REQUEST] = function (Container $container) {
            return new MultiCartToZedRequestClientBridge($container->getLocator()->zedRequest()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addPersistentCartClient(Container $container)
    {
        $container[static::CLIENT_PERSISTENT_CART] = function (Container $container) {
            return new MultiCartToPersistentCartClientBridge($container->getLocator()->persistentCart()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addMessengerClient(Container $container)
    {
        $container[static::CLIENT_MESSENGER] = function (Container $container) {
            return new MultiCartToMessengerClientBridge($container->getLocator()->messenger()->client());
        };

        return $container;
    }
}
