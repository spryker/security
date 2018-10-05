<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamationGui;

use Orm\Zed\SalesReclamation\Persistence\SpySalesReclamationQuery;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\SalesReclamationGui\Dependency\Facade\SalesReclamationGuiToSalesFacadeBridge;
use Spryker\Zed\SalesReclamationGui\Dependency\Facade\SalesReclamationGuiToSalesReclamationFacadeBridge;
use Spryker\Zed\SalesReclamationGui\Dependency\Service\SalesReclamationGuiToUtilDateTimeServiceBridge;

class SalesReclamationGuiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_SALES_RECLAMATION = 'FACADE_SALES_RECLAMATION';
    public const FACADE_SALES = 'FACADE_SALES';

    public const PROPEL_QUERY_SALES_RECLAMATION = 'PROPEL_QUERY_SALES_RECLAMATION';

    public const SERVICE_DATETIME = 'SERVICE_DATETIME';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container): Container
    {
        $this->addSalesFacade($container);
        $this->addSalesReclamationFacade($container);
        $this->addSalesReclamationPropelQuery($container);
        $this->addDateTimeService($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addSalesReclamationFacade(Container $container): Container
    {
        $container[static::FACADE_SALES_RECLAMATION] = function (Container $container) {
            return new SalesReclamationGuiToSalesReclamationFacadeBridge($container->getLocator()->salesReclamation()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addDateTimeService(Container $container): Container
    {
        $container[static::SERVICE_DATETIME] = function (Container $container) {
            return new SalesReclamationGuiToUtilDateTimeServiceBridge(
                $container->getLocator()->utilDateTime()->service()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addSalesReclamationPropelQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_SALES_RECLAMATION] = function (Container $container) {
            return SpySalesReclamationQuery::create();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addSalesFacade(Container $container): Container
    {
        $container[static::FACADE_SALES] = function (Container $container) {
            return new SalesReclamationGuiToSalesFacadeBridge($container->getLocator()->sales()->facade());
        };

        return $container;
    }
}
