<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyUnitAddress;

use Spryker\Zed\CompanyUnitAddress\Dependency\Facade\CompanyUnitAddressToCompanyBusinessUnitFacadeBridge;
use Spryker\Zed\CompanyUnitAddress\Dependency\Facade\CompanyUnitAddressToCountryFacadeBridge;
use Spryker\Zed\CompanyUnitAddress\Dependency\Facade\CompanyUnitAddressToLocaleFacadeBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class CompanyUnitAddressDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_COUNTRY = 'FACADE_COUNTRY';
    public const FACADE_LOCALE = 'FACADE_LOCALE';
    public const FACADE_COMPANY_BUSINESS_UNIT = 'FACADE_COMPANY_BUSINESS_UNIT';
    public const PLUGIN_ADDRESS_POST_UPDATE = 'PLUGIN_ADDRESS_POST_UPDATE';
    public const PLUGINS_ADDRESS_TRANSFER_HYDRATOR = 'PLUGINS_ADDRESS_TRANSFER_HYDRATOR';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container): Container
    {
        $container = parent::provideBusinessLayerDependencies($container);

        $container = $this->addCountryFacade($container);
        $container = $this->addLocaleFacade($container);
        $container = $this->addCompanyBusinessUnitFacade($container);
        $container = $this->addAddressPostUpdatePlugins($container);

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

        $container = $this->addAddressTransferHydratorPlugins($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCountryFacade(Container $container): Container
    {
        $container[static::FACADE_COUNTRY] = function (Container $container) {
            return new CompanyUnitAddressToCountryFacadeBridge($container->getLocator()->country()->facade());
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
            return new CompanyUnitAddressToLocaleFacadeBridge($container->getLocator()->locale()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addCompanyBusinessUnitFacade(Container $container): Container
    {
        $container[static::FACADE_COMPANY_BUSINESS_UNIT] = function (Container $container) {
            return new CompanyUnitAddressToCompanyBusinessUnitFacadeBridge($container->getLocator()->companyBusinessUnit()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addAddressPostUpdatePlugins(Container $container): Container
    {
        $container[static::PLUGIN_ADDRESS_POST_UPDATE] = function (Container $container) {
            return $this->getAddressPreUpdatePlugins();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addAddressTransferHydratorPlugins(Container $container): Container
    {
        $container[static::PLUGINS_ADDRESS_TRANSFER_HYDRATOR] = function (Container $container) {
            return $this->getAddressTransferHydratorPlugins();
        };

        return $container;
    }

    /**
     * @return \Spryker\Zed\CompanyUnitAddressExtension\Communication\Plugin\CompanyUnitAddressPreUpdatePluginInterface[]
     */
    protected function getAddressPreUpdatePlugins(): array
    {
        return [];
    }

    /**
     * @return \Spryker\Zed\CompanyUnitAddressExtension\Communication\Plugin\CompanyUnitAddressTransferHydratorPluginInterface[]
     */
    protected function getAddressTransferHydratorPlugins(): array
    {
        return [];
    }
}
