<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\UrlStorage;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\UrlStorage\Dependency\Facade\UrlStorageToEventBehaviorFacadeBridge;
use Spryker\Zed\UrlStorage\Dependency\Facade\UrlStorageToStoreFacadeBridge;
use Spryker\Zed\UrlStorage\Dependency\QueryContainer\UrlStorageToUrlQueryContainerBridge;
use Spryker\Zed\UrlStorage\Dependency\Service\UrlStorageToUtilSanitizeServiceBridge;

/**
 * @method \Spryker\Zed\UrlStorage\UrlStorageConfig getConfig()
 */
class UrlStorageDependencyProvider extends AbstractBundleDependencyProvider
{
    public const QUERY_CONTAINER_URL = 'QUERY_CONTAINER_URL';
    public const FACADE_EVENT_BEHAVIOR = 'FACADE_EVENT_BEHAVIOR';
    public const SERVICE_UTIL_SANITIZE = 'SERVICE_UTIL_SANITIZE';
    public const STORE = 'STORE';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        $this->addEventBehaviorFacade($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $this->addUtilSanitizeService($container);
        $this->addStore($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function providePersistenceLayerDependencies(Container $container)
    {
        $this->addUrlQueryContainer($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return void
     */
    protected function addUtilSanitizeService(Container $container)
    {
        $container[static::SERVICE_UTIL_SANITIZE] = function (Container $container) {
            return new UrlStorageToUtilSanitizeServiceBridge($container->getLocator()->utilSanitize()->service());
        };
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return void
     */
    protected function addEventBehaviorFacade(Container $container)
    {
        $container[static::FACADE_EVENT_BEHAVIOR] = function (Container $container) {
            return new UrlStorageToEventBehaviorFacadeBridge($container->getLocator()->eventBehavior()->facade());
        };
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return void
     */
    protected function addUrlQueryContainer(Container $container)
    {
        $container[static::QUERY_CONTAINER_URL] = function (Container $container) {
            return new UrlStorageToUrlQueryContainerBridge($container->getLocator()->url()->queryContainer());
        };
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return void
     */
    protected function addStore(Container $container)
    {
        $container[self::STORE] = function (Container $container) {
            return new UrlStorageToStoreFacadeBridge($container->getLocator()->store()->facade());
        };
    }
}
