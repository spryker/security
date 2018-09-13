<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\Mapper;

use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Exception\MissingThresholdFormMapperException;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\DataProvider\LocaleProvider;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\StoreCurrency\StoreCurrencyFinderInterface;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\MerchantRelationshipSalesOrderThresholdGuiConfig;

class ThresholdMapperResolver implements ThresholdMapperResolverInterface
{
    /**
     * @var \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\DataProvider\LocaleProvider
     */
    protected $localeProvider;

    /**
     * @var \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\StoreCurrency\StoreCurrencyFinderInterface
     */
    protected $storeCurrencyFinder;

    /**
     * @var \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\MerchantRelationshipSalesOrderThresholdGuiConfig
     */
    protected $config;

    /**
     * @param \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\DataProvider\LocaleProvider $localeProvider
     * @param \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\StoreCurrency\StoreCurrencyFinderInterface $storeCurrencyFinder
     * @param \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\MerchantRelationshipSalesOrderThresholdGuiConfig $config
     */
    public function __construct(LocaleProvider $localeProvider, StoreCurrencyFinderInterface $storeCurrencyFinder, MerchantRelationshipSalesOrderThresholdGuiConfig $config)
    {
        $this->localeProvider = $localeProvider;
        $this->storeCurrencyFinder = $storeCurrencyFinder;
        $this->config = $config;
    }

    /**
     * @param string $salesOrderThresholdTypeKey
     *
     * @throws \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Exception\MissingThresholdFormMapperException
     *
     * @return \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\Mapper\ThresholdFormMapperInterface
     */
    public function resolveThresholdMapperByStrategyKey(string $salesOrderThresholdTypeKey): ThresholdFormMapperInterface
    {
        if (!$this->hasThresholdMapperByStrategyKey($salesOrderThresholdTypeKey)) {
            throw new MissingThresholdFormMapperException();
        }
        /** @var \Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\Mapper\ThresholdFormMapperInterface $mapperClass */
        $mapperClass = $this->config->getStrategyTypeToFormTypeMap()[$salesOrderThresholdTypeKey];

        return new $mapperClass($this->localeProvider, $this->storeCurrencyFinder);
    }

    /**
     * @param string $salesOrderThresholdTypeKey
     *
     * @return bool
     */
    public function hasThresholdMapperByStrategyKey(string $salesOrderThresholdTypeKey): bool
    {
        return array_key_exists($salesOrderThresholdTypeKey, $this->config->getStrategyTypeToFormTypeMap());
    }
}
