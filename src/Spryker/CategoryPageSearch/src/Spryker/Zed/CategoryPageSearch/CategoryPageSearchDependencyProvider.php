<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CategoryPageSearch;

use Spryker\Shared\Kernel\Store;
use Spryker\Zed\CategoryPageSearch\Dependency\Facade\CategoryPageSearchToEventBehaviorFacadeBridge;
use Spryker\Zed\CategoryPageSearch\Dependency\Facade\CategoryPageSearchToSearchBridge;
use Spryker\Zed\CategoryPageSearch\Dependency\QueryContainer\CategoryPageSearchToCategoryQueryContainerBridge;
use Spryker\Zed\CategoryPageSearch\Dependency\QueryContainer\CategoryPageSearchToLocaleQueryContainerBridge;
use Spryker\Zed\CategoryPageSearch\Dependency\Service\CategoryPageSearchToUtilEncodingBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

/**
 * @method \Spryker\Zed\CategoryPageSearch\CategoryPageSearchConfig getConfig()
 */
class CategoryPageSearchDependencyProvider extends AbstractBundleDependencyProvider
{
    public const SERVICE_UTIL_ENCODING = 'SERVICE_UTIL_ENCODING';
    public const QUERY_CONTAINER_CATEGORY = 'QUERY_CONTAINER_CATEGORY';
    public const QUERY_CONTAINER_LOCALE = 'QUERY_CONTAINER_LOCALE';
    public const FACADE_CATEGORY = 'FACADE_CATEGORY';
    public const FACADE_EVENT_BEHAVIOR = 'FACADE_EVENT_BEHAVIOR';
    public const FACADE_SEARCH = 'FACADE_SEARCH';
    public const STORE = 'store';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        $container[static::FACADE_EVENT_BEHAVIOR] = function (Container $container) {
            return new CategoryPageSearchToEventBehaviorFacadeBridge($container->getLocator()->eventBehavior()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container[static::STORE] = function (Container $container) {
            return Store::getInstance();
        };

        $container[static::SERVICE_UTIL_ENCODING] = function (Container $container) {
            return new CategoryPageSearchToUtilEncodingBridge($container->getLocator()->utilEncoding()->service());
        };

        $container[self::FACADE_SEARCH] = function (Container $container) {
            return new CategoryPageSearchToSearchBridge($container->getLocator()->search()->facade());
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
        $container[static::QUERY_CONTAINER_CATEGORY] = function (Container $container) {
            return new CategoryPageSearchToCategoryQueryContainerBridge($container->getLocator()->category()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_LOCALE] = function (Container $container) {
            return new CategoryPageSearchToLocaleQueryContainerBridge($container->getLocator()->locale()->queryContainer());
        };

        return $container;
    }
}
