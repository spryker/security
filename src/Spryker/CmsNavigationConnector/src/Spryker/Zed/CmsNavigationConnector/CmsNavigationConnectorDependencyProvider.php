<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsNavigationConnector;

use Spryker\Zed\CmsNavigationConnector\Dependency\Facade\CmsNavigationConnectorToNavigationFacadeBridge;
use Spryker\Zed\CmsNavigationConnector\Dependency\QueryContainer\CmsNavigationConnectorToCmsQueryContainerBridge;
use Spryker\Zed\CmsNavigationConnector\Dependency\QueryContainer\CmsNavigationConnectorToNavigationQueryContainerBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class CmsNavigationConnectorDependencyProvider extends AbstractBundleDependencyProvider
{
    const FACADE_NAVIGATION = 'FACADE_NAVIGATION';
    const QUERY_CONTAINER_CMS = 'QUERY_CONTAINER_CMS';
    const QUERY_CONTAINER_NAVIGATION = 'QUERY_CONTAINER_NAVIGATION';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container[self::QUERY_CONTAINER_CMS] = function (Container $container) {
            return new CmsNavigationConnectorToCmsQueryContainerBridge($container->getLocator()->cms()->queryContainer());
        };

        $container[self::QUERY_CONTAINER_NAVIGATION] = function (Container $container) {
            return new CmsNavigationConnectorToNavigationQueryContainerBridge($container->getLocator()->navigation()->queryContainer());
        };

        $container[self::FACADE_NAVIGATION] = function (Container $container) {
            return new CmsNavigationConnectorToNavigationFacadeBridge($container->getLocator()->navigation()->facade());
        };

        return $container;
    }
}
