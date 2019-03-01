<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui;

use Orm\Zed\MerchantRelationship\Persistence\SpyMerchantRelationshipQuery;
use Orm\Zed\MerchantRelationshipSalesOrderThreshold\Persistence\SpyMerchantRelationshipSalesOrderThresholdQuery;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToCompanyFacadeBridge;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToCurrencyFacadeBridge;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToLocaleFacadeBridge;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToMerchantRelationshipFacadeBridge;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToMerchantRelationshipSalesOrderThresholdFacadeBridge;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToMoneyFacadeBridge;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Dependency\Facade\MerchantRelationshipSalesOrderThresholdGuiToStoreFacadeBridge;

/**
 * @method \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\MerchantRelationshipSalesOrderThresholdGuiConfig getConfig()
 */
class MerchantRelationshipSalesOrderThresholdGuiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_CURRENCY = 'FACADE_CURRENCY';
    public const FACADE_STORE = 'FACADE_STORE';
    public const FACADE_MERCHANT_RELATIONSHIP_SALES_ORDER_THRESHOLD = 'FACADE_MERCHANT_RELATIONSHIP_SALES_ORDER_THRESHOLD';
    public const FACADE_MERCHANT_RELATIONSHIP = 'FACADE_MERCHANT_RELATIONSHIP';
    public const FACADE_MONEY = 'FACADE_MONEY';
    public const FACADE_LOCALE = 'FACADE_LOCALE';
    public const FACADE_COMPANY = 'FACADE_COMPANY';

    public const PROPEL_QUERY_MERCHANT_RELATIONSHIP = 'PROPEL_QUERY_MERCHANT_RELATIONSHIP';
    public const PROPEL_QUERY_MERCHANT_RELATIONSHIP_SALES_ORDER_THRESHOLD = 'PROPEL_QUERY_MERCHANT_RELATIONSHIP_SALES_ORDER_THRESHOLD';

    public const SALES_ORDER_THRESHOLD_FORM_EXPANDER_PLUGINS = 'SALES_ORDER_THRESHOLD_FORM_EXPANDER_PLUGINS';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container): Container
    {
        $container = parent::provideCommunicationLayerDependencies($container);

        $container = $this->addCurrencyFacade($container);
        $container = $this->addStoreFacade($container);
        $container = $this->addMoneyFacade($container);
        $container = $this->addLocaleFacade($container);
        $container = $this->addMerchantRelationshipSalesOrderThresholdFacade($container);
        $container = $this->addMerchantRelationshipFacade($container);
        $container = $this->addCompanyFacade($container);

        $container = $this->addSalesOrderThresholdFormExpanderPlugins($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function providePersistenceLayerDependencies(Container $container): Container
    {
        $container = parent::providePersistenceLayerDependencies($container);

        $container = $this->addMerchantRelationshipPropelQuery($container);
        $container = $this->addMerchantRelationshipSalesOrderThresholdPropelQuery($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCurrencyFacade(Container $container): Container
    {
        $container[static::FACADE_CURRENCY] = function (Container $container) {
            return new MerchantRelationshipSalesOrderThresholdGuiToCurrencyFacadeBridge($container->getLocator()->currency()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addStoreFacade(Container $container): Container
    {
        $container[static::FACADE_STORE] = function (Container $container) {
            return new MerchantRelationshipSalesOrderThresholdGuiToStoreFacadeBridge($container->getLocator()->store()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMoneyFacade(Container $container): Container
    {
        $container[static::FACADE_MONEY] = function (Container $container) {
            return new MerchantRelationshipSalesOrderThresholdGuiToMoneyFacadeBridge($container->getLocator()->money()->facade());
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
            return new MerchantRelationshipSalesOrderThresholdGuiToLocaleFacadeBridge($container->getLocator()->locale()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMerchantRelationshipSalesOrderThresholdFacade(Container $container): Container
    {
        $container[static::FACADE_MERCHANT_RELATIONSHIP_SALES_ORDER_THRESHOLD] = function (Container $container) {
            return new MerchantRelationshipSalesOrderThresholdGuiToMerchantRelationshipSalesOrderThresholdFacadeBridge(
                $container->getLocator()->merchantRelationshipSalesOrderThreshold()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMerchantRelationshipFacade(Container $container): Container
    {
        $container[static::FACADE_MERCHANT_RELATIONSHIP] = function (Container $container) {
            return new MerchantRelationshipSalesOrderThresholdGuiToMerchantRelationshipFacadeBridge(
                $container->getLocator()->merchantRelationship()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCompanyFacade(Container $container): Container
    {
        $container[static::FACADE_COMPANY] = function (Container $container) {
            return new MerchantRelationshipSalesOrderThresholdGuiToCompanyFacadeBridge(
                $container->getLocator()->company()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMerchantRelationshipPropelQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_MERCHANT_RELATIONSHIP] = function () {
            return SpyMerchantRelationshipQuery::create();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMerchantRelationshipSalesOrderThresholdPropelQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_MERCHANT_RELATIONSHIP_SALES_ORDER_THRESHOLD] = function () {
            return SpyMerchantRelationshipSalesOrderThresholdQuery::create();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addSalesOrderThresholdFormExpanderPlugins(Container $container): Container
    {
        $container[static::SALES_ORDER_THRESHOLD_FORM_EXPANDER_PLUGINS] = function (Container $container) {
            return $this->getSalesOrderThresholdFormExpanderPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGuiExtension\Dependency\Plugin\SalesOrderThresholdFormExpanderPluginInterface[]
     */
    protected function getSalesOrderThresholdFormExpanderPlugins(): array
    {
        return [];
    }
}
