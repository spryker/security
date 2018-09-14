<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesOrderThresholdGui\Communication\Form\Mapper;

use Spryker\Zed\SalesOrderThresholdGui\Communication\Exception\MissingGlobalThresholdFormMapperException;
use Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\LocaleProvider;
use Spryker\Zed\SalesOrderThresholdGui\Communication\StoreCurrency\StoreCurrencyFinderInterface;
use Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig;

class GlobalThresholdMapperResolver implements GlobalThresholdMapperResolverInterface
{
    /**
     * @var \Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\LocaleProvider
     */
    protected $localeProvider;

    /**
     * @var \Spryker\Zed\SalesOrderThresholdGui\Communication\StoreCurrency\StoreCurrencyFinderInterface
     */
    protected $storeCurrencyFinder;

    /**
     * @var \Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig
     */
    protected $config;

    /**
     * @param \Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\LocaleProvider $localeProvider
     * @param \Spryker\Zed\SalesOrderThresholdGui\Communication\StoreCurrency\StoreCurrencyFinderInterface $storeCurrencyFinder
     * @param \Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig $config
     */
    public function __construct(LocaleProvider $localeProvider, StoreCurrencyFinderInterface $storeCurrencyFinder, SalesOrderThresholdGuiConfig $config)
    {
        $this->localeProvider = $localeProvider;
        $this->storeCurrencyFinder = $storeCurrencyFinder;
        $this->config = $config;
    }

    /**
     * @param string $salesOrderThresholdTypeKey
     *
     * @throws \Spryker\Zed\SalesOrderThresholdGui\Communication\Exception\MissingGlobalThresholdFormMapperException
     *
     * @return \Spryker\Zed\SalesOrderThresholdGui\Communication\Form\Mapper\GlobalThresholdFormMapperInterface
     */
    public function resolveGlobalThresholdMapperByStrategyKey(string $salesOrderThresholdTypeKey): GlobalThresholdFormMapperInterface
    {
        if (!$this->hasGlobalThresholdMapperByStrategyKey($salesOrderThresholdTypeKey)) {
            throw new MissingGlobalThresholdFormMapperException();
        }
        /** @var \Spryker\Zed\SalesOrderThresholdGui\Communication\Form\Mapper\GlobalThresholdFormMapperInterface $mapperClass */
        $mapperClass = $this->config->getStrategyTypeToFormTypeMap()[$salesOrderThresholdTypeKey];

        return new $mapperClass($this->localeProvider, $this->storeCurrencyFinder);
    }

    /**
     * @param string $salesOrderThresholdTypeKey
     *
     * @return bool
     */
    public function hasGlobalThresholdMapperByStrategyKey(string $salesOrderThresholdTypeKey): bool
    {
        return array_key_exists($salesOrderThresholdTypeKey, $this->config->getStrategyTypeToFormTypeMap());
    }
}
