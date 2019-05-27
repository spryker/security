<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesMerchantConnector\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\SalesMerchantConnector\Business\MerchantOrderReference\OrderItemReferences;
use Spryker\Zed\SalesMerchantConnector\Business\MerchantOrderReference\OrderItemReferencesInterface;

/**
 * @method \Spryker\Zed\SalesMerchantConnector\SalesMerchantConnectorConfig getConfig()
 */
class SalesMerchantConnectorBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\SalesMerchantConnector\Business\MerchantOrderReference\OrderItemReferencesInterface
     */
    public function createOrderItemReference(): OrderItemReferencesInterface
    {
        return new OrderItemReferences();
    }
}
