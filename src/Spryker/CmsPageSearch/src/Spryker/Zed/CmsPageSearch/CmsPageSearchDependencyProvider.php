<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsPageSearch;

use Spryker\Shared\Kernel\Store;
use Spryker\Zed\CmsPageSearch\Dependency\Facade\CmsPageSearchToCmsBridge;
use Spryker\Zed\CmsPageSearch\Dependency\Facade\CmsPageSearchToEventBehaviorFacadeBridge;
use Spryker\Zed\CmsPageSearch\Dependency\Facade\CmsPageSearchToSearchBridge;
use Spryker\Zed\CmsPageSearch\Dependency\QueryContainer\CmsPageSearchToCmsQueryContainerBridge;
use Spryker\Zed\CmsPageSearch\Dependency\QueryContainer\CmsPageSearchToLocaleQueryContainerBridge;
use Spryker\Zed\CmsPageSearch\Dependency\Service\CmsPageSearchToUtilEncodingBridge;
use Spryker\Zed\CmsPageSearch\Dependency\Service\CmsPageSearchToUtilSanitizeServiceBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class CmsPageSearchDependencyProvider extends AbstractBundleDependencyProvider
{
    const QUERY_CONTAINER_CMS_PAGE = 'QUERY_CONTAINER_CMS_PAGE';
    const QUERY_CONTAINER_LOCALE = 'QUERY_CONTAINER_LOCALE';
    const SERVICE_UTIL_SYNCHRONIZATION = 'SERVICE_UTIL_SYNCHRONIZATION';
    const SERVICE_UTIL_ENCODING = 'SERVICE_UTIL_ENCODING';
    const FACADE_CMS = 'FACADE_CMS';
    const FACADE_SEARCH = 'FACADE_SEARCH';
    const FACADE_EVENT_BEHAVIOR = 'FACADE_EVENT_BEHAVIOR';
    const SERVICE_UTIL_SANITIZE = 'SERVICE_UTIL_SANITIZE';
    const STORE = 'store';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        $container[static::SERVICE_UTIL_SANITIZE] = function (Container $container) {
            return new CmsPageSearchToUtilSanitizeServiceBridge($container->getLocator()->utilSanitize()->service());
        };

        $container[static::FACADE_EVENT_BEHAVIOR] = function (Container $container) {
            return new CmsPageSearchToEventBehaviorFacadeBridge($container->getLocator()->eventBehavior()->facade());
        };

        $container[static::SERVICE_UTIL_ENCODING] = function (Container $container) {
            return new CmsPageSearchToUtilEncodingBridge($container->getLocator()->utilEncoding()->service());
        };

        $container[static::FACADE_CMS] = function (Container $container) {
            return new CmsPageSearchToCmsBridge($container->getLocator()->cms()->facade());
        };

        $container[static::STORE] = function (Container $container) {
            return Store::getInstance();
        };

        $container[self::FACADE_SEARCH] = function (Container $container) {
            return new CmsPageSearchToSearchBridge($container->getLocator()->search()->facade());
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
        $container[static::QUERY_CONTAINER_CMS_PAGE] = function (Container $container) {
            return new CmsPageSearchToCmsQueryContainerBridge($container->getLocator()->cms()->queryContainer());
        };

        $container[static::QUERY_CONTAINER_LOCALE] = function (Container $container) {
            return new CmsPageSearchToLocaleQueryContainerBridge($container->getLocator()->locale()->queryContainer());
        };

        return $container;
    }
}
