<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Quote;

use Spryker\Client\Currency\Plugin\CurrencyPlugin;
use Spryker\Client\Kernel\AbstractDependencyProvider;
use Spryker\Client\Kernel\Container;
use Spryker\Client\Quote\Dependency\Client\QuoteToCurrencyClientBridge;
use Spryker\Client\Quote\Dependency\Client\QuoteToCustomerClientBridge;
use Spryker\Client\Quote\Dependency\Plugin\QuoteToCurrencyBridge;

/**
 * @method \Spryker\Client\Quote\QuoteConfig getConfig()
 */
class QuoteDependencyProvider extends AbstractDependencyProvider
{
    public const CLIENT_SESSION = 'session client';

    public const CURRENCY_PLUGIN = 'currency plugin';
    public const QUOTE_TRANSFER_EXPANDER_PLUGINS = 'QUOTE_TRANSFER_EXPANDER_PLUGINS';
    public const CLIENT_CUSTOMER = 'CLIENT_CUSTOMER';
    public const SERVICE_ZED = 'SERVICE_ZED';
    public const CLIENT_CURRENCY = 'CLIENT_CURRENCY';
    public const PLUGINS_ALLOWABLE_DATABASE_STRATEGY = 'PLUGINS_ALLOWABLE_DATABASE_STRATEGY';

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    public function provideServiceLayerDependencies(Container $container)
    {
        $container = $this->addSessionClient($container);
        $container = $this->addCurrencyPlugin($container);
        $container = $this->addQuoteTransferExpanderPlugins($container);
        $container = $this->addCustomerClient($container);
        $container = $this->addZedSevice($container);
        $container = $this->addCurrencyClient($container);
        $container = $this->addAllowableDatabaseStrategyPlugins($container);

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
            return $container->getLocator()->session()->client();
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addCurrencyPlugin(Container $container)
    {
        $container[static::CURRENCY_PLUGIN] = function (Container $container) {
            return new QuoteToCurrencyBridge(new CurrencyPlugin());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addQuoteTransferExpanderPlugins(Container $container)
    {
        $container[static::QUOTE_TRANSFER_EXPANDER_PLUGINS] = function (Container $container) {
            return $this->getQuoteTransferExpanderPlugins($container);
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addAllowableDatabaseStrategyPlugins(Container $container)
    {
        $container[static::PLUGINS_ALLOWABLE_DATABASE_STRATEGY] = function (Container $container) {
            return $this->getAllowableDatabaseStrategyPlugins($container);
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addCustomerClient(Container $container)
    {
        $container[static::CLIENT_CUSTOMER] = function (Container $container) {
            return new QuoteToCustomerClientBridge($container->getLocator()->customer()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addZedSevice(Container $container)
    {
        $container[self::SERVICE_ZED] = function (Container $container) {
            return $container->getLocator()->zedRequest()->client();
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addCurrencyClient(Container $container): Container
    {
        $container[static::CLIENT_CURRENCY] = function (Container $container) {
            return new QuoteToCurrencyClientBridge($container->getLocator()->currency()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Quote\Dependency\Plugin\QuoteTransferExpanderPluginInterface[]
     */
    protected function getQuoteTransferExpanderPlugins(Container $container)
    {
        return [];
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Zed\QuoteExtension\Dependency\Plugin\AllowableDatabaseStrategyPluginInterface[]
     */
    protected function getAllowableDatabaseStrategyPlugins(Container $container)
    {
        return [];
    }
}
