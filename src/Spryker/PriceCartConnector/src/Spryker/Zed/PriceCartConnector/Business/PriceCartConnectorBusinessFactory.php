<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceCartConnector\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\PriceCartConnector\Business\Manager\PriceManager;
use Spryker\Zed\PriceCartConnector\PriceCartConnectorDependencyProvider;

/**
 * @method \Spryker\Zed\PriceCartConnector\Business\PriceCartConnectorBusinessFactory getFactory()
 * @method \Spryker\Zed\PriceCartConnector\PriceCartConnectorConfig getConfig()
 */
class PriceCartConnectorBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @param string|null $grossPriceType
     *
     * @return \Spryker\Zed\PriceCartConnector\Business\Manager\PriceManager
     */
    public function createPriceManager($grossPriceType = null)
    {
        if ($grossPriceType === null) {
            $bundleConfig = $this->getConfig();
            $grossPriceType = $bundleConfig->getGrossPriceType();
        }

        return new PriceManager($this->getPriceFacade(), $grossPriceType, $this->getConfig()->getPriceMode());
    }

    /**
     * @return \Spryker\Zed\PriceCartConnector\Dependency\Facade\PriceCartToPriceInterface
     */
    protected function getPriceFacade()
    {
        return $this->getProvidedDependency(PriceCartConnectorDependencyProvider::FACADE_PRICE);
    }
}
