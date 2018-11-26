<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\ThresholdGroup\Resolver;

use Spryker\Zed\SalesOrderThresholdGui\Communication\Exception\MissingThresholdDataProviderException;
use Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\ThresholdGroup\ThresholdStrategyDataProviderInterface;
use Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig;

class GlobalThresholdDataProviderResolver implements GlobalThresholdDataProviderResolverInterface
{
    /**
     * @var \Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig
     */
    protected $config;

    /**
     * @var array|\Spryker\Zed\SalesOrderThresholdExtension\Dependency\Plugin\SalesOrderThresholdFormExpanderPluginInterface[]
     */
    protected $formExpanderPlugins;

    /**
     * @param \Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig $config
     * @param \Spryker\Zed\SalesOrderThresholdExtension\Dependency\Plugin\SalesOrderThresholdFormExpanderPluginInterface[] $formExpanderPlugins
     */
    public function __construct(SalesOrderThresholdGuiConfig $config, array $formExpanderPlugins)
    {
        $this->config = $config;
        $this->formExpanderPlugins = $formExpanderPlugins;
    }

    /**
     * @param string $salesOrderThresholdTypeGroup
     *
     * @throws \Spryker\Zed\SalesOrderThresholdGui\Communication\Exception\MissingThresholdDataProviderException
     *
     * @return \Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\ThresholdGroup\ThresholdStrategyDataProviderInterface
     */
    public function resolveGlobalThresholdDataProviderByStrategyGroup(string $salesOrderThresholdTypeGroup): ThresholdStrategyDataProviderInterface
    {
        if (!$this->hasGlobalThresholdDataProviderByStrategyGroup($salesOrderThresholdTypeGroup)) {
            throw new MissingThresholdDataProviderException();
        }
        /** @var \Spryker\Zed\SalesOrderThresholdGui\Communication\Form\DataProvider\ThresholdGroup\ThresholdStrategyDataProviderInterface $dataProvider */
        $dataProvider = $this->config->getStrategyGroupToDataProviderMap()[$salesOrderThresholdTypeGroup];

        return new $dataProvider($this->formExpanderPlugins);
    }

    /**
     * @param string $salesOrderThresholdTypeGroup
     *
     * @return bool
     */
    public function hasGlobalThresholdDataProviderByStrategyGroup(string $salesOrderThresholdTypeGroup): bool
    {
        return array_key_exists($salesOrderThresholdTypeGroup, $this->config->getStrategyGroupToDataProviderMap());
    }
}
